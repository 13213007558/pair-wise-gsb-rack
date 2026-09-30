# frozen_string_literal: true

require_relative 'urlmap'

module Rack; end
Rack::BUILDER_TOPLEVEL_BINDING = ->(builder){builder.instance_eval{binding}}

module Rack
  # Rack::Builder provides a domain-specific language (DSL) to construct Rack
  # applications. It is primarily used to parse +config.ru+ files which
  # instantiate several middleware and a final application which are hosted
  # by a Rack-compatible web server.
  #
  # Example:
  #
  #   app = Rack::Builder.new do
  #     use Rack::CommonLogger
  #     map "/ok" do
  #       run lambda { |env| [200, {'content-type' => 'text/plain'}, ['OK']] }
  #     end
  #   end
  #
  #   run app
  #
  # Or
  #
  #   app = Rack::Builder.app do
  #     use Rack::CommonLogger
  #     run lambda { |env| [200, {'content-type' => 'text/plain'}, ['OK']] }
  #   end
  #
  #   run app
  #
  # +use+ adds middleware to the stack, +run+ dispatches to an application.
  # You can use +map+ to construct a Rack::URLMap in a convenient way.
  class Builder
    # Error raised when the middleware ordering constraints declared via
    # the +before+ and +after+ options of #use cannot be satisfied, either
    # because they reference an unknown or ambiguous name, or because they
    # form a cycle.
    class OrderingError < ArgumentError; end

    # @private
    # Internal representation of a single #use statement: the proc that
    # instantiates the middleware, plus an optional local name and the
    # ordering constraints declared for it.
    class UseEntry
      attr_reader :name, :before, :after

      def initialize(wrapper, label, name = nil, before = nil, after = nil)
        @wrapper = wrapper
        @label = label
        @name = name
        @before = Array(before)
        @after = Array(after)
      end

      def call(app)
        @wrapper.call(app)
      end
      alias [] call

      def constrained?
        !!@name || !@before.empty? || !@after.empty?
      end

      def to_s
        @name ? "#{@label} (named #{@name.inspect})" : @label
      end
    end

    # https://stackoverflow.com/questions/2223882/whats-the-difference-between-utf-8-and-utf-8-without-bom
    UTF_8_BOM = '\xef\xbb\xbf'

    # Parse the given config file to get a Rack application.
    #
    # If the config file ends in +.ru+, it is treated as a
    # rackup file and the contents will be treated as if
    # specified inside a Rack::Builder block.
    #
    # If the config file does not end in +.ru+, it is
    # required and Rack will use the basename of the file
    # to guess which constant will be the Rack application to run.
    #
    # Examples:
    #
    #   Rack::Builder.parse_file('config.ru')
    #   # Rack application built using Rack::Builder.new
    #
    #   Rack::Builder.parse_file('app.rb')
    #   # requires app.rb, which can be anywhere in Ruby's
    #   # load path. After requiring, assumes App constant
    #   # is a Rack application
    #
    #   Rack::Builder.parse_file('./my_app.rb')
    #   # requires ./my_app.rb, which should be in the
    #   # process's current directory.  After requiring,
    #   # assumes MyApp constant is a Rack application
    def self.parse_file(path, **options)
      if path.end_with?('.ru')
        return self.load_file(path, **options)
      else
        require path
        return Object.const_get(::File.basename(path, '.rb').split('_').map(&:capitalize).join(''))
      end
    end

    # Load the given file as a rackup file, treating the
    # contents as if specified inside a Rack::Builder block.
    #
    # Ignores content in the file after +__END__+, so that
    # use of +__END__+ will not result in a syntax error.
    #
    # Example config.ru file:
    #
    #   $ cat config.ru
    #
    #   use Rack::ContentLength
    #   require './app.rb'
    #   run App
    def self.load_file(path, **options)
      config = ::File.read(path)
      config.slice!(/\A#{UTF_8_BOM}/) if config.encoding == Encoding::UTF_8

      if config[/^#\\(.*)/]
        fail "Parsing options from the first comment line is no longer supported: #{path}"
      end

      config.sub!(/^__END__\n.*\Z/m, '')

      return new_from_string(config, path, **options)
    end

    # Evaluate the given +builder_script+ string in the context of
    # a Rack::Builder block, returning a Rack application.
    def self.new_from_string(builder_script, path = "(rackup)", **options)
      builder = self.new(**options)

      # We want to build a variant of TOPLEVEL_BINDING with self as a Rack::Builder instance.
      # We cannot use instance_eval(String) as that would resolve constants differently.
      binding = BUILDER_TOPLEVEL_BINDING.call(builder)
      eval(builder_script, binding, path)

      return builder.to_app
    end

    # Initialize a new Rack::Builder instance.  +default_app+ specifies the
    # default application if +run+ is not called later.  If a block
    # is given, it is evaluated in the context of the instance.
    def initialize(default_app = nil, **options, &block)
      @use = []
      @map = nil
      @run = default_app
      @warmup = nil
      @freeze_app = false
      @options = options

      instance_eval(&block) if block_given?
    end

    # Any options provided to the Rack::Builder instance at initialization.
    # These options can be server-specific. Some general options are:
    #
    # * +:isolation+: One of +process+, +thread+ or +fiber+. The execution
    #   isolation model to use.
    attr :options

    # Create a new Rack::Builder instance and return the Rack application
    # generated from it.
    def self.app(default_app = nil, &block)
      self.new(default_app, &block).to_app
    end

    # Specifies middleware to use in a stack.
    #
    #   class Middleware
    #     def initialize(app)
    #       @app = app
    #     end
    #
    #     def call(env)
    #       env["rack.some_header"] = "setting an example"
    #       @app.call(env)
    #     end
    #   end
    #
    #   use Middleware
    #   run lambda { |env| [200, { "content-type" => "text/plain" }, ["OK"]] }
    #
    # All requests through to this application will first be processed by the middleware class.
    # The +call+ method in this example sets an additional environment key which then can be
    # referenced in the application if required.
    #
    # Middleware can be given a local +name+, and ordered relative to other
    # named middleware in the same stack using +before+ and +after+:
    #
    #   use SessionMiddleware, name: :session
    #   use AuditMiddleware, before: :auth
    #   use AuthMiddleware, name: :auth, after: :session
    #
    # +before+ and +after+ accept a single name or an array of names, and may
    # reference middleware declared later in the same stack (forward
    # references).  Constraints are resolved per stack: middleware declared
    # inside a +map+ block is ordered independently of middleware outside it.
    # Middleware without constraints keeps its declaration order.  Unknown
    # names, duplicate names, and cyclic constraints raise
    # Rack::Builder::OrderingError when the application is built.
    #
    # Note that +name+, +before+, and +after+ are reserved keywords and are
    # not passed on to the middleware.
    def use(middleware, *args, name: nil, before: nil, after: nil, **kwargs, &block)
      if @map
        mapping, @map = @map, nil
        @use << UseEntry.new(proc { |app| generate_map(app, mapping) }, "map(#{mapping.keys.join(', ')})")
      end
      @use << UseEntry.new(proc { |app| middleware.new(app, *args, **kwargs, &block) }, middleware.to_s, name, before, after)

      nil
    end

    # Takes a block or argument that is an object that responds to #call and
    # returns a Rack response.
    #
    # You can use a block:
    #
    #   run do |env|
    #     [200, { "content-type" => "text/plain" }, ["Hello World!"]]
    #   end
    #
    # You can also provide a lambda:
    #
    #   run lambda { |env| [200, { "content-type" => "text/plain" }, ["OK"]] }
    #
    # You can also provide a class instance:
    #
    #   class Heartbeat
    #     def call(env)
    #      [200, { "content-type" => "text/plain" }, ["OK"]]
    #     end
    #   end
    #
    #   run Heartbeat.new
    #
    def run(app = nil, &block)
      raise ArgumentError, "Both app and block given!" if app && block_given?

      @run = app || block

      nil
    end

    # Takes a lambda or block that is used to warm-up the application. This block is called
    # before the Rack application is returned by to_app.
    #
    #   warmup do |app|
    #     client = Rack::MockRequest.new(app)
    #     client.get('/')
    #   end
    #
    #   use SomeMiddleware
    #   run MyApp
    def warmup(prc = nil, &block)
      @warmup = prc || block
    end

    # Creates a route within the application.  Routes under the mapped path will be sent to
    # the Rack application specified by run inside the block.  Other requests will be sent to the
    # default application specified by run outside the block.
    #
    #   class App
    #     def call(env)
    #       [200, {'content-type' => 'text/plain'}, ["Hello World"]]
    #     end
    #   end
    #
    #   class Heartbeat
    #     def call(env)
    #       [200, { "content-type" => "text/plain" }, ["OK"]]
    #     end
    #   end
    #
    #   app = Rack::Builder.app do
    #     map '/heartbeat' do
    #       run Heartbeat.new
    #     end
    #     run App.new
    #   end
    #
    #   run app
    #
    # The +use+ method can also be used inside the block to specify middleware to run under a specific path:
    #
    #   app = Rack::Builder.app do
    #     map '/heartbeat' do
    #       use Middleware
    #       run Heartbeat.new
    #     end
    #     run App.new
    #   end
    #
    # This example includes a piece of middleware which will run before +/heartbeat+ requests hit +Heartbeat+.
    #
    # Note that providing a +path+ of +/+ will ignore any default application given in a +run+ statement
    # outside the block.
    def map(path, &block)
      @map ||= {}
      @map[path] = block

      nil
    end

    # Freeze the app (set using run) and all middleware instances when building the application
    # in to_app.
    def freeze_app
      @freeze_app = true
    end

    # Return the Rack application generated by this instance.
    def to_app
      app = @map ? generate_map(@run, @map) : @run
      fail "missing run or map statement" unless app
      app.freeze if @freeze_app
      app = resolve_order(@use).reverse.inject(app) { |a, e| e[a].tap { |x| x.freeze if @freeze_app } }
      @warmup.call(app) if @warmup
      app
    end

    # Call the Rack application generated by this builder instance. Note that
    # this rebuilds the Rack application and runs the warmup code (if any)
    # every time it is called, so it should not be used if performance is important.
    def call(env)
      to_app.call(env)
    end

    private

    # Generate a URLMap instance by generating new Rack applications for each
    # map block in this instance.
    def generate_map(default_app, mapping)
      mapped = default_app ? { '/' => default_app } : {}
      mapping.each { |r, b| mapped[r] = self.class.new(default_app, &b).to_app }
      URLMap.new(mapped)
    end

    # Resolve the final middleware order, honoring the +before+/+after+
    # constraints declared via #use.  Entries without constraints keep
    # their relative declaration order.  Raises OrderingError if a
    # constraint refers to an unknown name, a name is declared more than
    # once, or the constraints form a cycle.
    def resolve_order(entries)
      return entries unless entries.any?(&:constrained?)

      index_by_name = {}
      entries.each_with_index do |entry, index|
        next unless entry.name
        if index_by_name.key?(entry.name)
          raise OrderingError, "duplicate middleware name #{entry.name.inspect} declared by #{entry}"
        end
        index_by_name[entry.name] = index
      end

      # edges[i] lists the indexes of the entries that must come after
      # entries[i].
      edges = Array.new(entries.size) { [] }
      entries.each_with_index do |entry, index|
        entry.before.each do |ref|
          edges[index] << constraint_index(index_by_name, entry, ref, :before)
        end
        entry.after.each do |ref|
          edges[constraint_index(index_by_name, entry, ref, :after)] << index
        end
      end

      # Stable topological sort: among the entries that may be placed next,
      # always pick the one declared first, so unconstrained entries keep
      # their original relative order.
      incoming = Array.new(entries.size, 0)
      edges.each { |targets| targets.each { |target| incoming[target] += 1 } }
      remaining = (0...entries.size).to_a
      order = []
      until remaining.empty?
        index = remaining.find { |candidate| incoming[candidate].zero? }
        unless index
          chain = find_cycle(edges, remaining).map { |i| entries[i].to_s }.join(' -> ')
          raise OrderingError, "middleware ordering constraints contain a cycle: #{chain}"
        end
        order << entries[index]
        remaining.delete(index)
        edges[index].each { |target| incoming[target] -= 1 }
      end
      order
    end

    # Look up the index of the middleware named +ref+, raising a readable
    # OrderingError if no middleware in this stack carries that name.
    def constraint_index(index_by_name, entry, ref, relation)
      index_by_name.fetch(ref) do
        raise OrderingError, "#{entry} declares #{relation}: #{ref.inspect}, but no middleware in this stack is named #{ref.inspect}"
      end
    end

    # Find one concrete cycle among the entry indexes in +candidates+,
    # returning the indexes forming the cycle (with the first index
    # repeated at the end) so it can be shown as a readable chain.
    def find_cycle(edges, candidates)
      allowed = candidates.to_h { |i| [i, true] }
      state = {}
      path = []
      visit = lambda do |node|
        state[node] = :visiting
        path << node
        edges[node].each do |target|
          next unless allowed[target]
          if state[target] == :visiting
            return path[path.index(target)..] + [target]
          elsif state[target].nil?
            cycle = visit.call(target)
            return cycle if cycle
          end
        end
        path.pop
        state[node] = :visited
        nil
      end
      candidates.each do |node|
        next if state[node]
        cycle = visit.call(node)
        return cycle if cycle
      end
      nil
    end
  end
end
