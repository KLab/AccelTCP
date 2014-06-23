#include <limits.h>
#include "gtest/gtest.h"

extern "C"
{
/* #include "sample.h" */
}

 
TEST(SampleTest, AssertionTrue) {
  ASSERT_EQ(1, 1);
}
