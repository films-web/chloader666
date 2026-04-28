#pragma once
#include "poly_crypt.hpp"

namespace Constants {
    static __forceinline auto WsUrl() { return PCrypt("wss://ws.ch-sof2.online/connect"); }
    static __forceinline auto TargetExe() { return PCrypt("sof2mp.exe"); }
    static __forceinline auto IpcPipeName() { return PCrypt("\\\\.\\pipe\\CHPipe"); }
    static __forceinline auto AesTransportKey() { return PCrypt("Ch34tH4r4m_S3cr3t_K3y_256B1t_!!!"); }
    static __forceinline auto ClientSecret() { return PCrypt("baf0f0e65f1b2688b8d99cb628d21c9a07e8992174fe2f9cfc15cef7f92a6fb9"); }
}