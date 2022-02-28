#include <cstring>

#include "appspawn_server.h"
#include "hilog/log.h"

int main(int argc, char *const argv[])
{
    if (argc <= 1) {
        printf("appspawntools xxxx \n");
        return 0;
    }

    // calculate child process long name size
    uintptr_t start = reinterpret_cast<uintptr_t>(argv[0]);
    uintptr_t end = reinterpret_cast<uintptr_t>(strchr(argv[argc - 1], 0));
    uintptr_t argvSize = end - start;

    std::string appName(argv[1]);
    std::string uid ((argc > 2) ? argv[2] : ""); // 2 uid index
    auto appspawnServer = std::make_shared<OHOS::AppSpawn::AppSpawnServer>("AppSpawn");
    if (appspawnServer != nullptr) {
        int ret = appspawnServer->AppColdStart(argv[0], argvSize, appName, uid);
        if (ret != 0) {
            printf("Cold start %s fail \n", appName.c_str());
        }
    }
    return 0;
}
