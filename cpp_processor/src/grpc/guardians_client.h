#pragma once

#include "guardian.pb.h"
#include "guardian.grpc.pb.h"

class GuardiansClient {
    public:
    static void AuthenticateGuardian(const zera_guardian::GuardianPayloadResponse& my_response);
};