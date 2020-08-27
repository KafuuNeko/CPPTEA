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
    T **ptr_;
    size_t *size_;
    size_t *use_;
    
    void free()
    {
        if( ptr_ && use_ && --(*use_) == 0)
        {
            delete[] *ptr_;

            delete size_;
            delete use_;
            delete ptr_;

            use_ = nullptr, ptr_ = nullptr, size_ = nullptr;
        }
    }
public:
    ~basic_memory() { free(); }

    /* 普通构造函数 */
    basic_memory(T *ptr, size_t size)
        : ptr_(new T*(ptr)), size_(new size_t(size)), use_(new size_t(1)) {}

    basic_memory()
        : basic_memory(nullptr, 0) {}

    basic_memory(size_t size)
        : basic_memory(new T[size], size) { }
    
    basic_memory(const std::initializer_list<T> &il)
        : basic_memory(new(std::nothrow) T[il.size()], il.size()) { if(*ptr_) std::copy(il.begin(), il.end(), *ptr_); }

    /* 拷贝操作 */
    basic_memory(const basic_memory &rhs)
        : ptr_(rhs.ptr_), size_(rhs.size_), use_(rhs.use_) { if(use_) ++(*use_); }

    basic_memory &operator=(const basic_memory &rhs)
    {
        if(rhs.use_) ++(*rhs.use_);
        free();

        ptr_ = rhs.ptr_;
        size_ = rhs.size_;
        use_ = rhs.use_;

        return *this;
    }

    /* 移动操作 */
    basic_memory(basic_memory &&rhs) noexcept
        : ptr_(rhs.ptr_), size_(rhs.size_), use_(rhs.use_) { rhs.ptr_ = nullptr, rhs.size_ = nullptr, rhs.use_ = nullptr; }

    basic_memory &operator=(basic_memory &&rhs) noexcept
    {
        if(&rhs != this)
        {
            free();

            ptr_ = rhs.ptr_;
            size_ = rhs.size_;
            use_ = rhs.use_;

            rhs.ptr_ = nullptr, rhs.size_ = nullptr, rhs.use_ = nullptr;
        }

        return *this;
    }

    operator bool() const { return *ptr_; }

    T *get() const { return *ptr_; }

    T *last() const { return *ptr_?(*ptr_ + size()):nullptr; }

    void reset() { *ptr_ = nullptr, *size_ = 0; }

    void set(T *ptr, size_t size) { *ptr_ = ptr, *size_ = size; }

    size_t use() const { return *use_; }

    size_t size() const { return *size_; }

    void fill(const T &data) { if(*ptr_) std::fill(*ptr_, (*ptr_) + (*size_), data); }

};

using byte = uint8_t;
using Bytes = basic_memory<byte>;

constexpr int32_t kDelta = 0x9e3779b9;

/**
 * TEA密钥类
*/
struct Key
{
    Key(uint32_t key_a, uint32_t key_b, uint32_t key_c, uint32_t key_d)
    : key_a_(key_a), key_b_(key_b), key_c_(key_c), key_d_(key_d) {}

    Key(const byte (&key)[16])
    {
        key_a_ = reinterpret_cast<const int32_t*>(key)[0];
        key_b_ = reinterpret_cast<const int32_t*>(key)[1];
        key_c_ = reinterpret_cast<const int32_t*>(key)[2];
        key_d_ = reinterpret_cast<const int32_t*>(key)[3];
    }

    Key(const std::string &key)
    {
        key_a_ = key_b_ = key_c_ = key_d_ = 0;
        for (char ch : key)
        {
            key_a_ = key_a_ * 7 + ch;
            key_b_ = key_b_ * 15 + ch;
            key_c_ = key_c_ * 31 + ch;
            key_d_ = key_d_ * 63 + ch;
        }
    }

    uint32_t key_a_;
    uint32_t key_b_;
    uint32_t key_c_;
    uint32_t key_d_;
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
static void encrypt(const Bytes &content, const size_t &offset, const Key &key, const uint8_t &times, Bytes &result)
{
    uint64_t temp = *reinterpret_cast<const uint64_t *>(content.get() + offset);

    int32_t y = reinterpret_cast<int32_t*>(&temp)[0], 
            z = reinterpret_cast<int32_t*>(&temp)[1], 
            sum = 0;

    for (uint8_t i = 0; i < times; ++i)
    {
        sum += kDelta;
        y += ((z << 4) + key.key_a_) ^ (z + sum) ^ ((z >> 5) + key.key_b_);
        z += ((y << 4) + key.key_c_) ^ (y + sum) ^ ((y >> 5) + key.key_d_);
    }
    
    reinterpret_cast<int32_t*>(&temp)[0] = y;
    reinterpret_cast<int32_t*>(&temp)[1] = z;

    for(uint8_t i = 0; i < 8; ++i) result.get()[i] = reinterpret_cast<const byte*>(&temp)[i];
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
static void decrpy(const Bytes &encryptContent, const size_t &offset, const Key &key, const uint8_t &times, Bytes &result)
{
    uint64_t temp = *reinterpret_cast<const uint64_t *>(encryptContent.get() + offset);
    
    int32_t y = reinterpret_cast<int32_t*>(&temp)[0], 
            z = reinterpret_cast<int32_t*>(&temp)[1], 
            sum;

    if(times == 32)
        sum = 0xC6EF3720;///mDelta << 5;
    else if(times == 16)
        sum = 0xE3779B90;//mDelta << 4;
    else
        sum = kDelta * times;

    for (uint8_t i = 0; i < times; ++i)
    {
        z -= ((y << 4) + key.key_c_) ^ (y + sum) ^ ((y >> 5) + key.key_d_);
        y -= ((z << 4) + key.key_a_) ^ (z + sum) ^ ((z >> 5) + key.key_b_);
        sum -= kDelta;
    }

    reinterpret_cast<int32_t*>(&temp)[0] = y;
    reinterpret_cast<int32_t*>(&temp)[1] = z;

    for(uint8_t i = 0; i < 8; ++i) result.get()[i] = reinterpret_cast<const byte*>(&temp)[i];
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
static Bytes encrypt(const Bytes &content, const Key &key, const uint8_t &times = 32)
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
static Bytes decrpy(const Bytes &encryptContent, const Key &key, const uint8_t &times = 32)
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
inline Bytes encrypt_string(const std::string &content, const Key &key, const uint8_t &times = 32)
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
inline std::string decrpy_string(const Bytes &encryptContent, const Key &key, const uint8_t &times = 32)
{
    Bytes decrpy_data = decrpy(encryptContent, key, times);
    if (decrpy_data.size() < 8) return std::string();

    //校验Hash
    uint64_t hashValue = hash(reinterpret_cast<char*>(decrpy_data.get() + 8), decrpy_data.size() - 8);
    if (hashValue != *reinterpret_cast<uint64_t*>(decrpy_data.get())) return std::string();

    return std::string(reinterpret_cast<const char*>(decrpy_data.get() + 8), decrpy_data.size() - 8);
}


/**
 * 数据流加密
 * 将输入流加密，并将加密结果输出至加密结果输出流
 * 
 * @param   is      待加密的数据流
 *                  
 * @param   os      加密结果输出流
 * 
 * @param   key     TEA加密密钥
 * 
 * @param   times   加密轮数，默认32轮加密
 * 
 * @return  是否加密成功
*/
static bool encrypt(std::istream &is, std::ostream &os, const Key &key, const uint8_t &times = 32)
{
    Bytes buffer(8);
    Bytes result_buffer(8);

    is.seekg(std::istream::end);
    auto file_size = is.tellg();
    is.seekg(std::istream::beg);

    uint8_t fill_size = 8 - file_size % 8;
    uint8_t buffer_index = fill_size;

    buffer.get()[0] = static_cast<byte>(fill_size);
    if(buffer_index == 8)
    {
        buffer_index = 0;
        encrypt(buffer, 0, key, times, result_buffer);
        os.write(reinterpret_cast<char*>(result_buffer.get()), 8);
    }

    char read_byte;
    while(is.read(&read_byte, 1))
    {
        buffer.get()[buffer_index++] = read_byte;
        if(buffer_index == 8)
        {
            buffer_index = 0;
            encrypt(buffer, 0, key, times, result_buffer);
            os.write(reinterpret_cast<char*>(result_buffer.get()), 8);
        }
    }

    return buffer_index == 0;
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
static bool decrpy(std::istream &is, std::ostream &os, const Key &key, const uint8_t &times = 32)
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
                
                if(fill > 8) return false;
                if(fill != 8) os.write(reinterpret_cast<char*>(result_buffer.get() + fill), 8 - fill);
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
inline bool encrypt_file(const std::string &in_file, const std::string &out_file, const Key &key, const uint8_t &times = 32)
{
    std::ifstream en_ifs(in_file, std::ios::binary);
    std::ofstream en_ofs(out_file, std::ios::binary);

    std::unique_ptr<std::ifstream, decltype(__teafile_ifstream_close)*> en_ifs_close(&en_ifs, &__teafile_ifstream_close);
    std::unique_ptr<std::ofstream, decltype(__teafile_ofstream_close)*> en_ofs_close(&en_ofs, &__teafile_ofstream_close);

    return tea::encrypt(en_ifs, en_ofs, key, times);
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
inline bool decrpy_file(const std::string &in_file, const std::string &out_file, const Key &key, const uint8_t &times = 32)
{
    std::ifstream en_ifs(in_file, std::ios::binary);
    std::ofstream en_ofs(out_file, std::ios::binary);

    std::unique_ptr<std::ifstream, decltype(__teafile_ifstream_close)*> en_ifs_close(&en_ifs, &__teafile_ifstream_close);
    std::unique_ptr<std::ofstream, decltype(__teafile_ofstream_close)*> en_ofs_close(&en_ofs, &__teafile_ofstream_close);
    
    return tea::decrpy(en_ifs, en_ofs, key, times);
}

}

#endif

