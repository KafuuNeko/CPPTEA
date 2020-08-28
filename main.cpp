#include <iostream>
#include "tea.h"
#include <string>

inline void print(const tea::Bytes &bytes)
{
    for (size_t i = 0; i < bytes.size(); i++)
    {
        if (i == 0)
        {
            std::cout << (int)bytes.get()[i];
        }
        else
        {
            std::cout << ", " << (int)bytes.get()[i];
        }
    }

    std::cout << std::endl;
    
}

int main()
{
    tea::Key key("123456789");

    //while(true)
    {

    
    tea::Bytes content({1, 2, 3, 4, 5, 6, 7, 8, 9});

    tea::Bytes en_result = tea::encrypt_string("Hello World", key, 16);
    print(en_result);
    std::string de_result = tea::decrpy_string(en_result, key, 16);
    std::cout << de_result << std::endl;

    tea::encrypt_file("C:\\Users\\root\\Desktop\\83514122_p0_master1200.jpg", "C:\\Users\\root\\Desktop\\83514122_p0_master1200.jpg.tea", key);
    tea::decrpy_file("C:\\Users\\root\\Desktop\\83514122_p0_master1200.jpg.tea", "C:\\Users\\root\\Desktop\\83514122_p0_master1200.jpg.dec.jpg", key);

    }

    std::cin.get();
    return 0;
}