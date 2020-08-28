#ifndef __TEA_H
#define __TEA_H

/**
 * @author KafuuNeko
 * https://kafuu.cc/
 * gmail: kafuuneko@gmail.com
 *
*/

#include <inttypes.h>
#include <initializer_list>
#include <string>
#include <fstream>
#include <memory>

namespace tea
{

template<class T>
class basic_memory {
    T       **ptr_;
    size_t  *size_;
    size_t  *use_;
    bool    *release_;

    void free()
    {
        if( ptr_ && use_ && release_ && --(*use_) == 0)
        {
            if(*release_) delete[] *ptr_;

            delete release_;
            delete size_;
            delete use_;
            delete ptr_;


            use_ = nullptr, ptr_ = nullptr, size_ = nullptr;
        }
    }
public:
    ~basic_memory() { free(); }

    /* 普通构造函数 */
    basic_memory(T *ptr, size_t size, bool release = true)
        : ptr_(new T*(ptr)), size_(new size_t(size)), use_(new size_t(1)), release_(new bool(release)) {}

    basic_memory()
        : basic_memory(nullptr, 0) {}

    basic_memory(size_t size)
        : basic_memory(new T[size], size) { }

    basic_memory(const std::initializer_list<T> &il)
        : basic_memory(new(std::nothrow) T[il.size()], il.size()) { if(*ptr_) std::copy(il.begin(), il.end(), *ptr_); }

    /* 拷贝操作 */
    basic_memory(const basic_memory &rhs)
        : ptr_(rhs.ptr_), size_(rhs.size_), use_(rhs.use_), release_(rhs.release_) { if(use_) ++(*use_); }

    basic_memory &operator=(const basic_memory &rhs)
    {
        if(rhs.use_) ++(*rhs.use_);
        free();

        ptr_        = rhs.ptr_;
        size_       = rhs.size_;
        use_        = rhs.use_;
        release_    = rhs.release_;

        return *this;
    }

    /* 移动操作 */
    basic_memory(basic_memory &&rhs) noexcept
        : ptr_(rhs.ptr_), size_(rhs.size_), use_(rhs.use_), release_(rhs.release_) { rhs.ptr_ = nullptr, rhs.size_ = nullptr, rhs.use_ = nullptr, rhs.release_ = nullptr; }

    basic_memory &operator=(basic_memory &&rhs) noexcept
    {
        if(&rhs != this)
        {
            free();

            ptr_        = rhs.ptr_;
            size_       = rhs.size_;
            use_        = rhs.use_;
            release_    = rhs.release_;

            rhs.ptr_ = nullptr, rhs.size_ = nullptr, rhs.use_ = nullptr, rhs.release_ = nullptr;
        }

        return *this;
    }

    operator bool() const { return *ptr_; }

    T *get() const { return *ptr_; }

    T *last() const { return *ptr_?(*ptr_ + size()):nullptr; }

    void reset() { *ptr_ = nullptr, *size_ = 0, *release_ = false; }

    void set(T *ptr, size_t size, bool release = true) { *ptr_ = ptr, *size_ = size, *release_ = release; }

    size_t use() const { return *use_; }

    size_t size() const { return *size_; }

    void fill(const T &data) { if(*ptr_) std::fill(*ptr_, (*ptr_) + (*size_), data); }

};

using byte  = uint8_t;
using Bytes = basic_memory<byte>;

constexpr int32_t kDelta = 0x9e3779b9;

/**
 * TEA密钥类
*/
struct Key
{
    struct Segment {
        uint32_t a = 0;
        uint32_t b = 0;
        uint32_t c = 0;
        uint32_t d = 0;
    };

    Key(const Segment &keyseg) : seg(keyseg) {}

    Key(const byte (&key)[16])
    {
        seg = *reinterpret_cast<const Segment*>(key);
    }

    Key(const std::string &key)
    {
        for (char ch : key)
        {
            seg.a = seg.a * 7 +  static_cast<uint8_t>(ch);
            seg.b = seg.b * 15 + static_cast<uint8_t>(ch);
            seg.c = seg.c * 31 + static_cast<uint8_t>(ch);
            seg.d = seg.d * 63 + static_cast<uint8_t>(ch);
        }
    }

    Segment seg;
};

inline uint64_t bytesToInt64(const Bytes &bytes, const size_t &offset)
{
    uint64_t result = 0;

    for(size_t i = 0; i < 8; ++i)
    {
        result = (result << 8) + bytes.get()[offset + i];
    }

    return result;
}

inline void int64ToBytes(const uint64_t &value, const Bytes &bytes, const size_t &offset)
{
    for(size_t i = 0; i < 8; ++i)
    {
        bytes.get()[offset + 7 - i] = (value >> 8 * i) & 0xFF;
    }
}

union Int64ToInt32
{
    uint64_t value;
    struct { uint32_t y; uint32_t z;};
};

/**
 * TEA加密
 * 加密固定的八个字节
 *
 * @param   content     加密内容
 *
 * @param   offset      加密内容数据偏移
 *                      将对加密内容offset后的八个字节进行加密操作
 *
 * @param   key         TEA加密密钥
 *
 * @param   times       加密轮数，推荐32轮加密
 *
 * @param   result      加密结果，需传入固定八字节的Bytes
*/
static void encrypt(const Bytes &content, const size_t &offset, const Key &key, const uint32_t &times, Bytes &result)
{
    Int64ToInt32 temp;
    temp.value = bytesToInt64(content, offset);

    int32_t y = temp.y, z = temp.z, sum = 0;

    for (size_t i = 0; i < times; ++i)
    {
        sum = static_cast<int32_t>(static_cast<int64_t>(sum) + kDelta);
        y += ((z << 4) + key.seg.a) ^ (z + sum) ^ ((z >> 5) + key.seg.b);
        z += ((y << 4) + key.seg.c) ^ (y + sum) ^ ((y >> 5) + key.seg.d);
    }

    temp.y = y;
    temp.z = z;

    int64ToBytes(temp.value, result, 0);
}

/**
 * TEA解密
 * 解密固定的八个字节
 *
 * @param   encryptContent  密文数据内容
 *
 * @param   offset          解密内容数据偏移
 *                          将对密文数据offset后的八个字节进行解密操作
 *
 * @param   key             TEA加密密钥
 *
 * @param   times           解密轮数，推荐32轮加密
 *
 * @param   result          解密结果，需传入固定八字节的Bytes
*/
static void decrpy(const Bytes &encryptContent, const size_t &offset, const Key &key, const uint32_t &times, Bytes &result)
{
    Int64ToInt32 temp;
    temp.value = bytesToInt64(encryptContent, offset);

    int32_t y = temp.y, z = temp.z, sum;

    if(times == 32)
        sum = 0xC6EF3720;///mDelta << 5;
    else if(times == 16)
        sum = 0xE3779B90;//mDelta << 4;
    else
        sum = kDelta * times;

    for (size_t i = 0; i < times; ++i)
    {
        z -= ((y << 4) + key.seg.c) ^ (y + sum) ^ ((y >> 5) + key.seg.d);
        y -= ((z << 4) + key.seg.a) ^ (z + sum) ^ ((z >> 5) + key.seg.b);
        sum = static_cast<int32_t>(static_cast<int64_t>(sum) - kDelta);
    }

    temp.y = y;
    temp.z = z;

    int64ToBytes(temp.value, result, 0);
}

/**
 * 对自由尺寸的字节集进行加密
 * 若加密的数据长度+1非八位对齐，将进行填充
 *
 * @param   content     等待加密的数据
 *
 * @param   key         加密密钥
 *
 * @param   times       加密轮数，默认32轮加密
 *
 * @return 返回加密后的密文数据，若加密失败则返回空Bytes
 *
*/
static Bytes encrypt(const Bytes &content, const Key &key, const uint32_t &times = 32)
{
    if (!content) return Bytes();

    size_t size = content.size();

    byte fill = 8 - size % 8;
    Bytes encryptData(size + fill);

    if(!encryptData) return Bytes();

    encryptData.get()[0] = fill;

    std::copy(content.get(), content.last(), encryptData.get() + fill);

    Bytes temp(8);
    for (size_t offset = 0; offset < size + fill; offset += 8)
    {
        encrypt(encryptData, offset, key, times, temp);
        std::copy(temp.get(), temp.last(), encryptData.get() + offset);
    }

    return encryptData;
}

/**
 * 对自由尺寸的字节集进行解密
 *
 * @param   encryptContent      待解密的密文数据
 *
 * @param   key                 TEA加密密钥
 *
 * @param   times               TEA加密轮数，默认32轮加密
 *
 * @return 返回解密后的明文数据，若解密失败则返回空Bytes
*/
static Bytes decrpy(const Bytes &encryptContent, const Key &key, const uint32_t &times = 32)
{
    if(!encryptContent || (encryptContent.size() % 8)) return Bytes();

    Bytes tempDecrypt;

    size_t writeOffset = 0;

    Bytes temp(8);
    for (size_t offset = 0; offset < encryptContent.size(); offset += 8)
    {
        decrpy(encryptContent, offset, key, times, temp);
        if (offset == 0)
        {
            uint8_t fill = temp.get()[0];
            if(fill > 8) break;

            size_t decrpysize = encryptContent.size() - fill;

            tempDecrypt.set(new byte[decrpysize], decrpysize);

            if(fill < 8)
            {
                std::copy(temp.get() + fill, temp.last(), tempDecrypt.get() + writeOffset);
                writeOffset += 8 - fill;
            }
        }
        else
        {
            std::copy(temp.get(), temp.last(), tempDecrypt.get() + writeOffset);
            writeOffset += 8;
        }
    }

    return tempDecrypt;
}

/**
 * 辅助函数-取字符串哈希值
 *
 * @param   data    c风格字符串
 *
 * @param   len     字符串数据长度
 *
 * @return  哈希值
*/
static uint64_t hash(const char *data, size_t len)
{
    uint64_t hashValue = 0;
    for (size_t i = 0; i < len; i++)
        hashValue = hashValue * 31 + data[i];
    return hashValue;
}

/**
 * 对字符串数据进行加密
 * 基于对自由尺寸的字节集进行解密
 * 带有hash验证，加密时将计算字符串的hash值，解密时比对hash
 *
 * @param   content     待加密的数据内容
 *
 * @param   key         TEA加密密钥
 *
 * @param   times       TEA加密轮数
 *
 * @return  返回加密后的密文数据，若加密失败则返回空Bytes
 *
*/
inline Bytes encrypt_string(const std::string &content, const Key &key, const uint32_t &times = 32)
{
    //uint64_t hashValue = static_cast<uint64_t>(std::hash<std::string>()(content));
    uint64_t hashValue = hash(content.c_str(), content.length());

    Bytes encrypt_bytes(content.length() + 8);
    std::copy(reinterpret_cast<byte*>(&hashValue), reinterpret_cast<byte*>(&hashValue) + 8, encrypt_bytes.get());
    std::copy(content.begin(), content.end(), encrypt_bytes.get() + 8);

    auto result = encrypt(encrypt_bytes, key, times);
    return result;
}

/**
 * 解密数据为字符串
 * 基于对自由尺寸的字节集进行解密
 * 带有hash验证，加密时将计算字符串的hash值，解密时比对hash
 *
 * @param   encryptContent      待解密的密文数据
 *
 * @param   key                 TEA加密密钥
 *
 * @param   times               TEA加密轮数，默认32轮加密
 *
 * @return  返回解密后的字符串，若加密失败则返回空字符串
*/
inline std::string decrpy_string(const Bytes &encryptContent, const Key &key, const uint32_t &times = 32, bool *status_flag = nullptr)
{
    Bytes decrpy_data = decrpy(encryptContent, key, times);
    if (decrpy_data.size() < 8)
    {
        if(status_flag) *status_flag = false;
        return std::string();
    }

    //校验Hash
    uint64_t hashValue = hash(reinterpret_cast<char*>(decrpy_data.get() + 8), decrpy_data.size() - 8);
    if (hashValue != *reinterpret_cast<uint64_t*>(decrpy_data.get()))
    {
        if(status_flag) *status_flag = false;
        return std::string();
    }

    if(status_flag) *status_flag = true;
    return std::string(reinterpret_cast<const char*>(decrpy_data.get() + 8), decrpy_data.size() - 8);
}


/**
 * 数据流加密
 * 将输入流加密，并将加密结果输出至加密结果输出流
 *
 * @param   is              待加密的数据流
 *
 * @param   os              加密结果输出流
 *
 * @param   instream_size   数据流大小
 *
 * @param   key             TEA加密密钥
 *
 * @param   times           加密轮数，默认32轮加密
 *
 * @return  是否加密成功
*/
static bool encrypt(std::istream &is, std::ostream &os, size_t instream_size, const Key &key, const uint32_t &times = 32)
{
    Bytes buffer(8);
    Bytes result_buffer(8);

    uint8_t fill_size = 8 - instream_size % 8;
    uint8_t buffer_index = fill_size;

    buffer.get()[0] = static_cast<byte>(fill_size);
    if(buffer_index == 8)
    {
        buffer_index = 0;
        encrypt(buffer, 0, key, times, result_buffer);
        os.write(reinterpret_cast<char*>(result_buffer.get()), 8);
    }

    char read_byte;
    while(instream_size && is.read(&read_byte, 1))
    {
        --instream_size;
        buffer.get()[buffer_index++] = read_byte;
        if(buffer_index == 8)
        {
            buffer_index = 0;
            encrypt(buffer, 0, key, times, result_buffer);
            os.write(reinterpret_cast<char*>(result_buffer.get()), 8);
        }
    }

    return (instream_size == 0) && (buffer_index == 0);
}


/**
 * 数据流解密
 * 将输入流解密，并将解密结果输出至解密结果输出流
 *
 * @param   is      待解密的数据流
 *
 * @param   os      解密结果输出流
 *
 * @param   key     TEA加密密钥
 *
 * @param   times   加密轮数，默认32轮加密
 *
 * @return  是否解密成功
*/
static bool decrpy(std::istream &is, std::ostream &os, const Key &key, const uint32_t &times = 32)
{
    Bytes buffer(8);
    Bytes result_buffer(8);

    bool first_flag = true;

    uint8_t buffer_index = 0;

    char read_byte;
    while(is.read(&read_byte, 1))
    {
        buffer.get()[buffer_index++] = read_byte;
        if (buffer_index == 8)
        {
            buffer_index = 0;

            decrpy(buffer, 0, key, times, result_buffer);

            if (first_flag)
            {
                first_flag = false;
                uint8_t fill = static_cast<uint8_t>(result_buffer.get()[0]);

                if(fill > 8)
                    return false;

                if(fill != 8)
                    os.write(reinterpret_cast<char*>(result_buffer.get() + fill), 8 - fill);
            }
            else
            {
                os.write(reinterpret_cast<char*>(result_buffer.get()), 8);
            }
        }
    }

    return buffer_index == 0;
}


static void __teafile_ifstream_close(std::ifstream *is){ is->close(); }
static void __teafile_ofstream_close(std::ofstream *os){ os->close(); }

/**
 * 文件加密
 * 基于数据流加密
 *
 * @param   in_file     待加密的文件路径
 *
 * @param   out_file    加密结果输出的文件路径
 *
 * @param   key         TEA加密密钥
 *
 * @param   times       加密轮数，默认32轮加密
 *
 * @return 是否加密成功
 *
*/
inline bool encrypt_file(const std::string &in_file, const std::string &out_file, const Key &key, const uint32_t &times = 32)
{
    std::ifstream en_ifs(in_file, std::ios::binary);
    std::ofstream en_ofs(out_file, std::ios::binary);

    size_t file_size = 0;

    //获取文件大小
    char tempch;
    while(en_ifs.read(&tempch, 1)) ++file_size;

    en_ifs.clear(std::ios::eofbit);
    en_ifs.seekg(std::ios::beg);

    std::unique_ptr<std::ifstream, decltype(__teafile_ifstream_close)*> en_ifs_close(&en_ifs, &__teafile_ifstream_close);
    std::unique_ptr<std::ofstream, decltype(__teafile_ofstream_close)*> en_ofs_close(&en_ofs, &__teafile_ofstream_close);

    return tea::encrypt(en_ifs, en_ofs, file_size, key, times);
}

/**
 * 文件解密
 * 基于数据流解密
 *
 * @param   in_file     待解密的文件路径
 *
 * @param   out_file    解密结果输出的文件路径
 *
 * @param   key         TEA加密密钥
 *
 * @param   times       加密轮数，默认32轮加密
 *
 * @return 是否解密成功
 *
*/
inline bool decrpy_file(const std::string &in_file, const std::string &out_file, const Key &key, const uint32_t &times = 32)
{
    std::ifstream de_ifs(in_file, std::ios::binary);
    std::ofstream de_ofs(out_file, std::ios::binary);

    std::unique_ptr<std::ifstream, decltype(__teafile_ifstream_close)*> en_ifs_close(&de_ifs, &__teafile_ifstream_close);
    std::unique_ptr<std::ofstream, decltype(__teafile_ofstream_close)*> en_ofs_close(&de_ofs, &__teafile_ofstream_close);

    return tea::decrpy(de_ifs, de_ofs, key, times);
}

}

#endif

