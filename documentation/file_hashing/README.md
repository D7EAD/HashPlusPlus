<h1>Using Hash++ to Generate File Hashes</h1>
Much like how hashes can be generated using generic data, Hash++ provides functions for developers to find hashes for files and files in nested directories. The signatures for the methods can be found below.

```
static hashpp::hash getFileHash(hashpp::ALGORITHMS algorithm, const std::string& path);
static hashpp::hashCollection getFilesHashes(const FilePathsContainer& filePathSet);
static hashpp::hashCollection getFilesHashes(const std::vector<FilePathsContainer>& filePathSets);
static hashpp::hashCollection getFilesHashes(const std::initializer_list<FilePathsContainer>& filePathSets);
```

<br>
Some file hashing functions, much like some other components of the library, make use of their own <code>Container</code> alias <code>FilePathsContainer</code> (if you have not read about the <code>Container</code> class used by Hash++, please see the documentation for <b>Hashing</b>). You can find an example of a single file being hashed below.
https://github.com/D7EAD/HashPlusPlus/blob/ba418167da59826cda2a18990a90cf332d75308e/documentation/file_hashing/getFileHash/getFileHash_usage.cpp#L10-L29

<br>
If you're in the business of hashing multiple files at once, you can find an example of such a use below.
https://github.com/D7EAD/HashPlusPlus/blob/c007af7d81bdf054a389314ad1d7bbb6d0757262/documentation/file_hashing/getFilesHashes/getFilesHashes_usage.cpp#L14-L35
