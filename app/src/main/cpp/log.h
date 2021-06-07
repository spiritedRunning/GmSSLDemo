//
// Created by Zach on 2021/6/7.
//

#ifndef GMSSLDEMO_LOG_H
#define GMSSLDEMO_LOG_H

#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "CAMERA_LIVE", __VA_ARGS__)

#endif //GMSSLDEMO_LOG_H
