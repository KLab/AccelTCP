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


TEST(HttpHandlerTest, HttpRequestSettingsTest_00) {
  struct http_parser_settings *expected = NULL;
  struct http_parser_settings *actual = &http_request_settings;
  ASSERT_NE(expected, actual);
}

