//
// Created by yale on 11/25/19.
//

#include "sbvector.h"


int sbvector::cuthead(uint32_t _size) {
	if (_size >= size()) {
		resize(0);
		return 0;
	} else {
		erase(begin(), begin() + _size);
		return size();
	}

}

