#include <limits.h>
#include "gtest/gtest.h"

extern "C"
{
#include "http_parser.h"
}

// 
 
TEST(HttpParserTest, AssertionTrue) {
  ASSERT_EQ(1, 1);
}

