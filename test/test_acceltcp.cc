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


TEST(AcceltcpTest, AcceltcpTest_00) {
  int expected = -1;
  int argc = 1;
  char *argv[] = {"acceltcp_unittest"};
  int actual = acceltcp(argc, argv);
  EXPECT_EQ(expected, actual);
}


TEST(AcceltcpTest, AcceltcpTest_01) {
  int expected = 0;
  int argc = 2;
  char *argv[] = {"acceltcp_unittest", "-V"};
  int actual = acceltcp(argc, argv);
  EXPECT_EQ(expected, actual);
}


TEST(AcceltcpTest, AcceltcpTest_02) {
  int expected = -1;
  int argc = 2;
  char *argv[] = {"acceltcp_unittest", "-h"};
  int actual = acceltcp(argc, argv);
  EXPECT_EQ(expected, actual);
}


TEST(AcceltcpTest, OptionParseTest_00) {
  int expected = 0;
  int argc = -1;
  char *argv[] = {"acceltcp_unittest"};
  struct config config;
  int actual = option_parse(argc, argv, &config);
  EXPECT_EQ(expected, actual);
}


TEST(AcceltcpTest, OptionParseTunnelTest_00) {
  int expected = -1;
  char *s = "";
  struct config_tunnel c;
  int actual = option_parse_tunnel(s, &c);
  EXPECT_EQ(expected, actual);
}


TEST(AcceltcpTest, TunnelSetupTest_00) {
  struct tunnel *expected = NULL;
  struct ev_loop *loop = NULL;
  struct config_tunnel c;
  struct tunnel *actual = tunnel_setup(loop, &c);
  EXPECT_EQ(expected, actual);
}

