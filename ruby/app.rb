require 'digest/sha1'
require 'mysql2'
require 'sinatra/base'
require 'logger'
require 'redis'
require 'json'

class App < Sinatra::Base
  configure do
    enable :logging
    set :session_secret, 'tonymoris'
    set :public_folder, File.expand_path('../../public', __FILE__)
    set :avatar_max_size, 1 * 1024 * 1024
    file = ::File.new('log/app.log', 'a+')
    file.sync = true
    logger = ::Logger.new(file)

    use Rack::CommonLogger, logger

    enable :sessions
  end

  configure :development do
    require 'sinatra/reloader'
    register Sinatra::Reloader
  end

  helpers do
    def user
      return @_user unless @_user.nil?

      user_id = session[:user_id]
      return nil if user_id.nil?

      @_user = db_get_user(user_id)
      if @_user.nil?
        params[:user_id] = nil
        return nil
      end

      @_user
    end
  end

  get '/initialize' do
    db.query("DELETE FROM user WHERE id > 1000")
    db.query("DELETE FROM image WHERE id > 1001")
    db.query("DELETE FROM channel WHERE id > 10")
    db.query("DELETE FROM message WHERE id > 10000")
    db.query("DELETE FROM haveread")

    rows = db.query('SELECT * FROM channel ORDER BY id')
    rows.each do |row|
     redis.set "channel_#{row['id']}", row['description']
    end

    rows = db.query('select channel_id, COUNT(*) cnt from message group by channel_id')
    rows.each do |row|
     redis.set "channel_message_#{row['channel_id']}", row['cnt']
    end
    204
  end

  get '/' do
    if session.has_key?(:user_id)
      return redirect '/channel/1', 303
    end
    erb :index
  end

  get '/channel/:channel_id' do
    if user.nil?
      return redirect '/login', 303
    end

    @channel_id = params[:channel_id].to_i
    @channels, @description = get_channel_list_info(@channel_id)
    erb :channel
  end

  get '/register' do
    erb :register
  end

  post '/register' do
    name = params[:name]
    pw = params[:password]
    if name.nil? || name.empty? || pw.nil? || pw.empty?
      return 400
    end
    begin
      user_id = register(name, pw)
    rescue Mysql2::Error => e
      return 409 if e.error_number == 1062
      raise e
    end
    session[:user_id] = user_id
    redirect '/', 303
  end

  get '/login' do
    erb :login
  end

  post '/login' do
    name = params[:name]
    statement = db.prepare('SELECT * FROM user WHERE name = ? limit 1')
    row = statement.execute(name).first
    statement.close
    if row.nil? || row['password'] != Digest::SHA1.hexdigest(row['salt'] + params[:password])
      return 403
    end
    session[:user_id] = row['id']
    redirect '/', 303
  end

  get '/logout' do
    session[:user_id] = nil
    redirect '/', 303
  end

  post '/message' do
    user_id = session[:user_id]
    message = params[:message]
    channel_id = params[:channel_id]
    if user_id.nil? || message.nil? || channel_id.nil? || user.nil?
      return 403
    end
    db_add_message(channel_id.to_i, user_id, message)
    204
  end

  get '/message' do
    user_id = session[:user_id]
    if user_id.nil?
      return 403
    end

    channel_id = params[:channel_id].to_i
    last_message_id = params[:last_message_id].to_i
    statement = db.prepare('SELECT a.id as id, a.created_at as created_at, a.content as content, b.name as name, b.display_name as display_name, b.avatar_icon as avatar_icon FROM message a inner join user b on a.user_id = b.id WHERE a.id > ? AND a.channel_id = ? ORDER BY a.id DESC LIMIT 100')
    rows = statement.execute(last_message_id, channel_id).to_a
    statement.close
    response = []
    rows.each do |row|
      r = {}
      r['id'] = row['id']
      r['user'] = {name: row['name'], display_name: row['display_name'], avatar_icon: row['avatar_icon']}
      r['date'] = row['created_at'].strftime("%Y/%m/%d %H:%M:%S")
      r['content'] = row['content']
      response << r
    end
    response.reverse!

    max_message_id = rows.empty? ? 0 : rows.map { |row| row['id'] }.max
    statement = db.prepare([
      'INSERT INTO haveread (user_id, channel_id, message_id, updated_at, created_at) ',
      'VALUES (?, ?, ?, NOW(), NOW()) ',
      'ON DUPLICATE KEY UPDATE message_id = ?, updated_at = NOW()',
    ].join)
    statement.execute(user_id, channel_id, max_message_id, max_message_id)
    statement.close

    content_type :json
    response.to_json
  end

  get '/fetch' do
    user_id = session[:user_id]
    if user_id.nil?
      return 403
    end

    res = []
    statement = db.prepare(<<-SQL
               select c.id as id,
               case when h.user_id is null then
               (select count(*) as cnt from message m where m.channel_id = c.id)
               else
               (select count(*) as cnt from message m where m.channel_id = c.id and m.id > h.message_id)
               end cnt
               from channel c left join haveread h on c.id = h.channel_id and h.user_id = ?
               SQL
    )
    rows = statement.execute(user_id)
    rows.each do |row|
      r = {}
      r['channel_id'] = row['id']
      r['unread'] = row['cnt']
      res << r
    end
    statement.close

    content_type :json
    res.to_json
  end

  get '/history/:channel_id' do
    if user.nil?
      return redirect '/login', 303
    end

    @channel_id = params[:channel_id].to_i

    @page = params[:page]
    if @page.nil?
      @page = '1'
    end
    if @page !~ /\A\d+\Z/ || @page == '0'
      return 400
    end
    @page = @page.to_i

    n = 20
    statement = db.prepare('SELECT a.id id, a.created_at created_at, a.content content, b.name name, b.display_name display_name, b.avatar_icon avatar_icon FROM message a inner join user b on a.user_id = b.id WHERE a.channel_id = ? ORDER BY a.id DESC LIMIT ? OFFSET ?')
    rows = statement.execute(@channel_id, n, (@page - 1) * n).to_a
    statement.close
    @messages = []
    rows.each do |row|
      r = {}
      r['id'] = row['id']
      r['user'] = {'name' => row['name'], 'display_name' => row['display_name'], 'avatar_icon' => row['avatar_icon']}
      r['date'] = row['created_at'].strftime("%Y/%m/%d %H:%M:%S")
      r['content'] = row['content']
      @messages << r
      #statement.close
    end
    @messages.reverse!

    cnt = (redis.get "channel_message_#{@channel_id}").to_f
    @max_page = cnt == 0 ? 1 :(cnt / n).ceil

    return 400 if @page > @max_page

    @channels, @description = get_channel_list_info(@channel_id)
    erb :history
  end

  get '/profile/:user_name' do
    if user.nil?
      return redirect '/login', 303
    end

    @channels, = get_channel_list_info

    user_name = params[:user_name]
    statement = db.prepare('SELECT * FROM user WHERE name = ? limit 1')
    @user = statement.execute(user_name).first
    statement.close

    if @user.nil?
      return 404
    end

    @self_profile = user['id'] == @user['id']
    erb :profile
  end
  
  get '/add_channel' do
    if user.nil?
      return redirect '/login', 303
    end

    @channels, = get_channel_list_info
    erb :add_channel
  end

  post '/add_channel' do
    if user.nil?
      return redirect '/login', 303
    end

    name = params[:name]
    description = params[:description]
    if name.nil? || description.nil?
      return 400
    end
    statement = db.prepare('INSERT INTO channel (name, description, updated_at, created_at) VALUES (?, ?, NOW(), NOW())')
    statement.execute(name, description)
    channel_id = db.last_id
    statement.close
    redis.set "channel_#{channel_id}", description
    redirect "/channel/#{channel_id}", 303
  end

  post '/profile' do
    if user.nil?
      return redirect '/login', 303
    end

    if user.nil?
      return 403
    end

    display_name = params[:display_name]
    avatar_name = nil
    avatar_data = nil

    file = params[:avatar_icon]
    unless file.nil?
      filename = file[:filename]
      if !filename.nil? && !filename.empty?
        ext = filename.include?('.') ? File.extname(filename) : ''
        unless ['.jpg', '.jpeg', '.png', '.gif'].include?(ext)
          return 400
        end

        if settings.avatar_max_size < file[:tempfile].size
          return 400
        end

        data = file[:tempfile].read
        digest = Digest::SHA1.hexdigest(data)

        avatar_name = digest + ext
        avatar_data = data
      end
    end

    if !avatar_name.nil? && !avatar_data.nil?
      path = File.expand_path('../../public', __FILE__) + "/icons/" + avatar_name
      File.open(path, 'w') do |f|
        f.print avatar_data
      end
      statement = db.prepare('UPDATE user SET avatar_icon = ? WHERE id = ?')
      statement.execute(avatar_name, user['id'])
      statement.close
    end

    if !display_name.nil? || !display_name.empty?
      statement = db.prepare('UPDATE user SET display_name = ? WHERE id = ?')
      statement.execute(display_name, user['id'])
      statement.close
    end

    redirect '/', 303
  end

  get '/debug/write' do
    rows = db.query('select * from image').to_a
    path = File.expand_path('../../public', __FILE__) + "/icons"
    rows.each do |row|
      file_name = path + '/' + row['name']
      File.open(file_name, 'w') do |f|
        f.print row['data']
      end
    end
    200
  end

  private

  def db
    return @db_client if defined?(@db_client)

    @db_client = Mysql2::Client.new(
      host: ENV.fetch('ISUBATA_DB_HOST') { 'localhost' },
      port: ENV.fetch('ISUBATA_DB_PORT') { '3306' },
      username: ENV.fetch('ISUBATA_DB_USER') { 'root' },
      password: ENV.fetch('ISUBATA_DB_PASSWORD') { '' },
      database: 'isubata',
      encoding: 'utf8mb4'
    )
    @db_client.query('SET SESSION sql_mode=\'TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY\'')
    @db_client
  end

  def redis
    r = Thread.current[:redis]
    return r unless r.nil?
    r = Redis.new(path: '/var/run/redis/redis.sock')
    Thread.current[:redis] = r
    r
  end

  def db_get_user(user_id)
    statement = db.prepare('SELECT * FROM user WHERE id = ?')
    user = statement.execute(user_id).first
    statement.close
    user
  end

  def db_add_message(channel_id, user_id, content)
    statement = db.prepare('INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())')
    messages = statement.execute(channel_id, user_id, content)
    statement.close
    redis.incr "channel_message_#{channel_id}"
    messages
  end

  def random_string(n)
    Array.new(20).map { (('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a).sample }.join
  end

  def register(user, password)
    salt = random_string(20)
    pass_digest = Digest::SHA1.hexdigest(salt + password)
    statement = db.prepare('INSERT INTO user (name, salt, password, display_name, avatar_icon, created_at) VALUES (?, ?, ?, ?, ?, NOW())')
    statement.execute(user, salt, pass_digest, user, 'default.png')
    row = db.query('SELECT LAST_INSERT_ID() AS last_insert_id').first
    statement.close
    row['last_insert_id']
  end

  def get_channel_list_info(focus_channel_id = nil)
    channels = db.query('SELECT * FROM channel ORDER BY id').to_a
    return [channels, ''] if focus_channel_id.nil?

    description = redis.get "channel_#{focus_channel_id}"
    [channels, description]
  end

  def ext2mime(ext)
    if ['.jpg', '.jpeg'].include?(ext)
      return 'image/jpeg'
    end
    if ext == '.png'
      return 'image/png'
    end
    if ext == '.gif'
      return 'image/gif'
    end
    ''
  end
end
