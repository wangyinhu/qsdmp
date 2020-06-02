//
// Created by yale on 11/25/19.
//

#ifndef INC_3918730A867D43F89A1D24FB7154FC3C_H
#define INC_3918730A867D43F89A1D24FB7154FC3C_H


#include <string>


class sbvector : public std::basic_string<uint8_t>  {
public:
	int cuthead(uint32_t _size);
};


#endif //INC_3918730A867D43F89A1D24FB7154FC3C_H
