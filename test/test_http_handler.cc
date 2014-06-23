#include <limits.h>
#include "gtest/gtest.h"

extern "C"
{
#include "http_handler.h"
}

// 
 
TEST(HttpHandlerTest, AssertionTrue) {
  ASSERT_EQ(1, 1);
}

