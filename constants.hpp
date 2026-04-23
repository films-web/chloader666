#pragma once
#include "poly_crypt.hpp"

namespace Constants {
    inline auto WsUrl() { return PCrypt("wss://ws.ch-sof2.online/connect"); }
    inline auto TargetExe() { return PCrypt("sof2mp.exe"); }
    inline auto IpcPipeName() { return PCrypt("\\\\.\\pipe\\CHPipe"); }
}