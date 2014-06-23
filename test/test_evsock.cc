#include <limits.h>
#include "gtest/gtest.h"

extern "C"
{
#include "evsock.h"
}

// 
 
TEST(EvsockTest, AssertionTrue) {
  ASSERT_EQ(1, 1);
}

