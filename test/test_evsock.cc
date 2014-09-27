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


TEST(EvsockTest, EvsockHandlerTest_00) {
  struct ev_loop *loop = NULL;
  struct ev_io *w = NULL;
  int revents;
  evsock_handler(loop, w, revents);
  EXPECT_EQ(1, 1);
}


TEST(EvsockTest, EvsockSuspendTest_00) {
  struct evsock *sock = NULL;
  int how;
  evsock_suspend (sock, how);
  EXPECT_EQ(1, 1);
}


TEST(EvsockTest, EvsockWakeupTest_00) {
  struct evsock *sock = NULL;
  int how;
  evsock_wakeup (sock, how);
  EXPECT_EQ(1, 1);
}

