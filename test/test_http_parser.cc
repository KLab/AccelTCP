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


TEST(HttpParserTest, HttpParserInitTest_00) {
  http_parser *parser = NULL;
  enum http_parser_type type;
  http_parser_init(parser, type);
  ASSERT_EQ(1, 1);
}


TEST(HttpParserTest, HttpParserExecuteTest_00) {
  http_parser *parser = NULL;
  http_parser_settings *settings = NULL;
  char *data = NULL;
  size_t len;
  size_t actual = http_parser_execute(parser, settings, data, len);
  ASSERT_EQ(1, 1);
}
