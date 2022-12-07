class Container {		
	public: // constructors
		Container() noexcept = default;
		Container(const Container& container) noexcept
			: algorithm(container.algorithm), key(container.key), data(container.data) {}
		Container(Container&& container) noexcept
			: algorithm(container.algorithm), key(std::move(container.key)), data(std::move(container.data)) {}
		Container(
			ALGORITHMS algorithm, 
			const std::vector<std::string>& data
		) noexcept : algorithm(algorithm), data(data) {}
		Container(
			ALGORITHMS algorithm, 
			std::vector<std::string>&& data
		) noexcept : algorithm(algorithm), data(std::move(data)) {}	
		Container(
			ALGORITHMS algorithm,
			const std::vector<std::string>& data,
			const std::string& key
		) noexcept : algorithm(algorithm), data(data), key(key) {}
		Container(
			ALGORITHMS algorithm,
			std::vector<std::string>&& data,
			const std::string& key
		) noexcept : algorithm(algorithm), data(std::move(data)), key(key) {}
		Container(
			ALGORITHMS algorithm,
			const std::vector<std::string>& data,
			std::string&& key
		) noexcept : algorithm(algorithm), data(data), key(std::move(key)) {}
		Container(
			ALGORITHMS algorithm,
			std::vector<std::string>&& data,
			std::string&& key
		) noexcept : algorithm(algorithm), data(std::move(data)), key(std::move(key)) {}		
	
		template <class... _Ts,
			std::enable_if_t<std::conjunction_v<std::is_constructible<std::string, _Ts>...>, int> = 0>
		Container(
			ALGORITHMS algorithm,
			const _Ts&... data
		) noexcept : algorithm(algorithm), data({ data... }) {}

		template <class... _Ts,
			std::enable_if_t<std::conjunction_v<std::is_constructible<std::string, _Ts>..., std::negation<std::is_lvalue_reference<_Ts>>...>, int> = 0>
		Container(
			ALGORITHMS algorithm,
			_Ts&&... data
		) noexcept : algorithm(algorithm), data({ std::forward<_Ts>(data)... }) {}
			
	public: // member functions
		constexpr const ALGORITHMS& getAlgorithm() const noexcept { return this->algorithm; }
		constexpr const std::string& getKey() const noexcept { return this->key; }
		constexpr const std::vector<std::string>& getData() const noexcept { return this->data; }
		void setAlgorithm(ALGORITHMS algorithm) noexcept { this->algorithm = algorithm; }
		void setKey(const std::string& key) noexcept { this->key = key; }
		
		void setData(const std::vector<std::string>& data) noexcept { this->data = data; }
		void setData(std::vector<std::string>&& data) noexcept { this->data = std::move(data); }
		template <class... _Ts> void setData(const _Ts&... data) noexcept { this->data = { data... }; }	
		template <class... _Ts,
			std::enable_if_t<std::conjunction_v<std::negation<std::is_lvalue_reference<_Ts>>...>, int> = 0>
		void setData(_Ts&&... data) noexcept { this->data = { std::forward<_Ts>(data)... }; }
			
		void appendData(const std::vector<std::string>& data) noexcept { this->data.insert(this->data.end(), data.begin(), data.end()); }
		void appendData(std::vector<std::string>&& data) noexcept { this->data.insert(this->data.end(), std::make_move_iterator(data.begin()), std::make_move_iterator(data.end())); }
		template <class... _Ts> void appendData(const _Ts&... data) noexcept { (this->data.push_back(data), ...); }
		template <class... _Ts,
			std::enable_if_t<std::conjunction_v<std::negation<std::is_lvalue_reference<_Ts>>...>, int> = 0>
		void appendData(_Ts&&... data) noexcept { (this->data.push_back(std::forward<_Ts>(data)), ...); }
			
		Container& operator=(const Container& _rhs) noexcept {
			if (this != &_rhs) {
				this->algorithm = _rhs.getAlgorithm();
				this->key = _rhs.getKey();
				this->data = _rhs.getData();
			}
			return *this;
		}

		Container& operator=(Container&& _rhs) noexcept {
			if (this != &_rhs) {
				this->algorithm = _rhs.algorithm;
				this->key = std::move(_rhs.key);
				this->data = std::move(_rhs.data);
			}
			return *this;
		}

	private: // member variables
		ALGORITHMS algorithm;
		std::string key;
			
		// Holds arbitrary data; how this data is defined is determined
		// by the functions that the container containing said data is passed to.
		//	(e.g., a call to getFilesHashes with a container will treat all data
		//  in it as paths to files to be hashed, and a call to getHashes with
		//  a container will treat all data as generic data to be hashed)
		std::vector<std::string> data;
};
