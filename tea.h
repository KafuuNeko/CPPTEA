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

};

using byte = uint8_t;
using Bytes = basic_memory<byte>;

constexpr int32_t kDelta = 0x9e3779b9;

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

static Bytes encrypt(const Bytes &content, const Key &key)
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
        encrypt(encryptData, offset, key, 32, temp);
        std::copy(temp.get(), temp.last(), encryptData.get() + offset);
    }
    
    return encryptData;
}

static Bytes decrpy(const Bytes &encryptContent, const Key &key)
{
    if(!encryptContent || (encryptContent.size() % 8)) return Bytes();

    Bytes tempDecrypt;

    size_t writeOffset = 0;

    Bytes temp(8);
    for (size_t offset = 0; offset < encryptContent.size(); offset += 8)
    {
        decrpy(encryptContent, offset, key, 32, temp);
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

static uint64_t hash(const char *data, size_t len)
{
    uint64_t hashValue = 0;
    for (size_t i = 0; i < len; i++)
        hashValue = hashValue * 31 + data[i];
    return hashValue;
}

static Bytes encrypt_string(const std::string &content, const Key &key)
{
    //uint64_t hashValue = static_cast<uint64_t>(std::hash<std::string>()(content));
    uint64_t hashValue = hash(content.c_str(), content.length());

    Bytes encrypt_bytes(content.length() + 8);
    std::copy(reinterpret_cast<byte*>(&hashValue), reinterpret_cast<byte*>(&hashValue) + 8, encrypt_bytes.get());
    std::copy(content.begin(), content.end(), encrypt_bytes.get() + 8);

    auto result = encrypt(encrypt_bytes, key);
    return result;
}

static std::string decrpy_string(const Bytes &encryptContent, const Key &key)
{
    Bytes decrpy_data = decrpy(encryptContent, key);
    if (decrpy_data.size() < 8) return std::string();

    //校验Hash
    uint64_t hashValue = hash(reinterpret_cast<char*>(decrpy_data.get() + 8), decrpy_data.size() - 8);
    if (hashValue != *reinterpret_cast<uint64_t*>(decrpy_data.get())) return std::string();

    return std::string(reinterpret_cast<const char*>(decrpy_data.get() + 8), decrpy_data.size() - 8);
}

}

#endif

