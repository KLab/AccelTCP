#include <limits.h>
#include "gtest/gtest.h"

extern "C"
{
#include "acceltcp.h"
}

// 
 
TEST(AcceltcpTest, AssertionTrue) {
  ASSERT_EQ(1, 1);
}


TEST(AcceltcpTest, OptionParseTunnelTest_00) {
  int expected = 0;
  char *s = "";
  struct config_tunnel c;
  int actual = option_parse_tunnel(s, &c);
  EXPECT_EQ(expected, actual);
}


TEST(AcceltcpTest, OptionParseTest_00) {
  int expected = 0;
  int argc = 1;
  char *argv[] = {""};
  struct config config;
  int actual = option_parse(argc, argv, &config);
  // EXPECT_EQ(expected, actual);
}


TEST(AcceltcpTest, ConfigDebugTest_00) {
  struct config expected;
  struct config actual;
  config_debug(&actual);
  // EXPECT_EQ(expected, actual);
}


TEST(AcceltcpTest, TunnelSetupTest_00) {
  struct tunnel *expected;
  struct ev_loop *loop;
  struct config_tunnel c;
  struct tunnel *actual = tunnel_setup(loop, &c);
  // EXPECT_EQ(expected, actual);
}

