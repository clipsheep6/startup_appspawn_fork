#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sched.h>

#define BASIC_MOUNT_FLAGS (MS_REC | MS_BIND)
#define FILE_MODE 0711

static int MakeDir(const char *dir, mode_t mode)
{
    int rc = -1;
    if (dir == NULL || *dir == '\0') {
        errno = EINVAL;
        return rc;
    }
    rc = mkdir(dir, mode);
    if (rc < 0 && errno != EEXIST) {
        return rc;
    }
    return 0;
}

static int MakeDirRecursive(const char *dir, mode_t mode)
{
    int rc = -1;
    char buffer[PATH_MAX] = {0};
    const char *p = nullptr;
    if (dir == nullptr || *dir == '\0') {
        errno = EINVAL;
        return rc;
    }
    p = dir;
    const char *slash = strchr(dir, '/');
    while (slash != nullptr) {
        int gap = slash - p;
        p = slash + 1;
        if (gap == 0) {
            slash = strchr(p, '/');
            continue;
        }
        if (gap < 0) { // end with '/'
            break;
        }
        if (memcpy_s(buffer, PATH_MAX, dir, p - dir - 1) != EOK) {
            return -1;
        }
        rc = MakeDir(buffer, mode);
        if (rc < 0) {
            return rc;
        }
        slash = strchr(p, '/');
    }
    return MakeDir(dir, mode);
}

static int32_t DoAppSandboxMountOnce(const char *originPath, const char *destinationPath,
                                            const char *fsType, unsigned long mountFlags,
                                            const char *options, mode_t mountSharedFlag)
{
    int ret = 0;
    // To make sure destinationPath exist
    ret = MakeDirRecursive(destinationPath, FILE_MODE);
    if (ret != 0) {
        printf("MakeDirRecursive for %s failed %d:%d.\n", destinationPath, ret, errno);
    }
    // to mount fs and bind mount files or directory
    ret = mount(originPath, destinationPath, fsType, mountFlags, options);
    if (ret != 0) {
        printf("mount from %s to %s failed %d:%d.\n", originPath, destinationPath, ret, errno);
        return ret;
    }
    ret = mount(NULL, destinationPath, NULL, mountSharedFlag, NULL);
    if (ret != 0) {
        printf("mount %s with shared flag %d failed %d:%d.\n", originPath, mountSharedFlag, ret, errno);
    }
    return ret;
}

static int DoSandboxRootFolderCreate(const char *sandboxPackagePath)
{
    int rc = mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL);
    if (rc != 0) {
        printf("mount / failed.\n");
        return rc;
    }
    return DoAppSandboxMountOnce(sandboxPackagePath, sandboxPackagePath, "",
                            BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);
}

static int ChangeCurrentDir(const char *sandboxPackagePath)
{
    int32_t ret = 0;
    ret = chdir(sandboxPackagePath);
    if (ret != 0) {
        printf("chdir failed, path is %s\n", sandboxPackagePath);
        return ret;
    }

    ret = syscall(SYS_pivot_root, sandboxPackagePath, sandboxPackagePath);
    if (ret != 0) {
        printf("errno is %d, pivot root failed, sandboxPackagePath is %s\n", errno, sandboxPackagePath);
        return ret;
    }

    ret = umount2(".", MNT_DETACH);
    if (ret != 0) {
        printf("MNT_DETACH failed, sandboxPackagePath is %s\n", sandboxPackagePath);
        return ret;
    }
    return ret;
}

#define SANDBOX_STAMP_FILE_SUFFIX ".stamp"

static int BuildSandboxPath(int userId, const char *packageName, const char *suffix, char *buf, int len)
{
    int ret;
    if (suffix == NULL) {
        suffix = "";
    }
    if ((packageName == NULL) || (packageName[0] == '\0')) {
        ret = snprintf(buf, len, "/mnt/sandbox/app-common/%d%s", userId, suffix);
    } else {
        ret = snprintf(buf, len, "/mnt/sandbox/app/%d/%s%s", userId, packageName, suffix);
    }
    return ret;
}

static void CreateSandboxStamp(int userId, const char *packageName)
{
    char name[PATH_MAX];
    BuildSandboxPath(userId, packageName, SANDBOX_STAMP_FILE_SUFFIX, name, sizeof(name));

    FILE *f = fopen(name, "wb");
    if (f != NULL) {
        fclose(f);
    }
}

static void RemoveSandboxStamp(int userId, const char *packageName)
{
    char name[PATH_MAX];
    BuildSandboxPath(userId, packageName, SANDBOX_STAMP_FILE_SUFFIX, name, sizeof(name));

    remove(name);
}

static int IsSandboxBindMounted(int userId, const char *packageName)
{
    char name[PATH_MAX];
    BuildSandboxPath(userId, packageName, SANDBOX_STAMP_FILE_SUFFIX, name, sizeof(name));

    FILE *f = fopen(name, "rb");
    if (f != NULL) {
        fclose(f);
        return 1;
    }
    return 0;
}

static void CreateCommonFileSystemSkelenton(int userId, int force)
{
    if (!force && IsSandboxBindMounted(userId, NULL)) {
        printf("Common FS Skelenton already created.\n");
        return;
    }

    char name[PATH_MAX];
    BuildSandboxPath(userId, NULL, NULL, name, sizeof(name));
    MakeDirRecursive(name, FILE_MODE);

    // Mount static paths for all apps
    BuildSandboxPath(userId, NULL, "/dev", name, sizeof(name));
    DoAppSandboxMountOnce("/dev", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    BuildSandboxPath(userId, NULL, "/proc", name, sizeof(name));
    DoAppSandboxMountOnce("/proc", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    BuildSandboxPath(userId, NULL, "/sys", name, sizeof(name));
    DoAppSandboxMountOnce("/sys", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    BuildSandboxPath(userId, NULL, "/system", name, sizeof(name));
    DoAppSandboxMountOnce("/system", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    BuildSandboxPath(userId, NULL, "/bin", name, sizeof(name));
    DoAppSandboxMountOnce("/bin", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    BuildSandboxPath(userId, NULL, "/lib", name, sizeof(name));
    DoAppSandboxMountOnce("/lib", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    BuildSandboxPath(userId, NULL, "/etc", name, sizeof(name));
    DoAppSandboxMountOnce("/etc", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    BuildSandboxPath(userId, NULL, "/chipset", name, sizeof(name));
    DoAppSandboxMountOnce("/chipset", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    BuildSandboxPath(userId, NULL, "/data/misc", name, sizeof(name));
    DoAppSandboxMountOnce("/data/misc", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    // Create stamp file
    CreateSandboxStamp(userId, NULL);
}

static void CreateAppPrivateBindMounts(int userId, const char *packageName, int force)
{
    char name[PATH_MAX];
    BuildSandboxPath(userId, packageName, NULL, name, sizeof(name));
    MakeDirRecursive(name, FILE_MODE);

    // Make it shared
    int ret = mount(name, name, NULL, MS_BIND | MS_REC, NULL);
    printf("mount-bind for data return %d:%d.\n", ret, errno);
    ret = mount(NULL, name, NULL, MS_SHARED, NULL);
    printf("make-shared return %d:%d.\n", ret, errno);

    // Mount app private paths
    char source[PATH_MAX];
    snprintf(source, sizeof(source), "/data/app/el1/100/base/%s", packageName);
    BuildSandboxPath(userId, packageName, "/data/storage/el1/base", name, sizeof(name));
    DoAppSandboxMountOnce(source, name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    snprintf(source, sizeof(source), "/data/app/el1/100/database/%s", packageName);
    BuildSandboxPath(userId, packageName, "/data/storage/el1/database", name, sizeof(name));
    DoAppSandboxMountOnce(source, name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    BuildSandboxPath(userId, NULL, "/data/storage/el1/bundle/systemResources", name, sizeof(name));
    DoAppSandboxMountOnce("/system/app/SystemResources", name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    // Create stamp file
    CreateSandboxStamp(userId, packageName);
}

static void DestroyAppPrivateBindMounts(int userId, const char *packageName)
{
    char name[PATH_MAX];
    RemoveSandboxStamp(userId, packageName);

    // umount app private paths
    BuildSandboxPath(userId, packageName, "/data/storage/el1/base", name, sizeof(name));
    int ret = umount(name);
    if (ret != 0) {
        printf("umount %s failed %d:%d\n", name, ret, errno);
    }

    BuildSandboxPath(userId, packageName, "/data/storage/el1/database", name , sizeof(name));
    ret = umount(name);
    if (ret != 0) {
        printf("umount %s failed %d:%d\n", name, ret, errno);
    }

    // umount app root path
    BuildSandboxPath(userId, packageName, NULL, name, sizeof(name));
    ret = umount(name);
    if (ret != 0) {
        printf("umount %s failed %d:%d\n", name, ret, errno);
        return;
    }

    char cmd[PATH_MAX];
    // Dangerous, if app root path umount filed, it will remove real data
    snprintf(cmd, sizeof(cmd), "rm -fr %s", name);
    system(cmd);
}

static void ChildProcess(int userId, const char *packageName, int force)
{
    // Create new mnt namespace
    int rc = unshare(CLONE_NEWNS);
    printf("ChildProcess %s unshare return %d.", packageName, rc);

    // Mount root folder
    char name[PATH_MAX];
    BuildSandboxPath(userId, NULL, NULL, name, sizeof(name));
    DoSandboxRootFolderCreate(name);

    CreateAppPrivateBindMounts(userId, packageName, force);

    BuildSandboxPath(userId, NULL, "/data/storage", name, sizeof(name));
    char app_data[PATH_MAX];
    BuildSandboxPath(userId, packageName, "/data/storage", app_data, sizeof(app_data));
    DoAppSandboxMountOnce(app_data, name, "", BASIC_MOUNT_FLAGS, NULL, MS_SLAVE);

    // Change to sandbox root path
    BuildSandboxPath(userId, NULL, NULL, name, sizeof(name));
    ChangeCurrentDir(name);

    while (1) {
        printf("Child process %s sleep now ...\n", packageName);
        sleep(10);
    }
}

static void usage(const char *name)
{
    printf("Usage: %s [OPTION]\n"
           "Do sandbox test.\n"
           "    -f, --force          Ignore stamp file, force to create mount binds again\n"
           "    -u, --umount         Umount app private sandbox\n"
           "    -h, --help           print this help info\n", name);
}

#define SANDBOX_USER_ID 100

#define PACKAGE_NAME "com.ohos.sceneboard"
#define PACKAGE_NAME2 "com.huawei.hmos.clock"

int main(int argc, char *argv[])
{
    int opt;
    int force = 0;

    while ((opt == getopt(argc, argv, "fuh")) != -1) {
        switch (opt) {
            case 'f':
                force = 1;
                break;
            case 'u':
                DestroyAppPrivateBindMounts(SANDBOX_USER_ID, PACKAGE_NAME);
                DestroyAppPrivateBindMounts(SANDBOX_USER_ID, PACKAGE_NAME2);
                exit(0);
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            default:
            break;
        }
    }

    CreateCommonFileSystemSkelenton(SANDBOX_USER_ID, force);

    pid_t pid = fork();
    if (pid > 0) {
        printf("parent wait for child now ...\n");

        pid = fork();
        if (pid > 0) {
            printf("Parent wait for child2 now ...\n");
            sleep(1000);
            return 0;
        } else if (pid < 0) {
            printf("Fork failed ...\n");
            return -1;
        }
    }

    // Child process
    ChildProcess(SANDBOX_USER_ID, PACKAGE_NAME, force);
}