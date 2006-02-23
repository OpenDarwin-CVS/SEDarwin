
#import <Cocoa/Cocoa.h>

int          global_argc;
const char **global_argv;

int main(int argc, const char *argv[])
{
    global_argc = argc-1;
    global_argv = argv+1;

    return NSApplicationMain(argc, argv);
}
