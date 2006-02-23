/* LabelDialog */

#import <Cocoa/Cocoa.h>

@interface LabelDialog : NSObject
{
    IBOutlet id labeltext;
    IBOutlet id menur;
    IBOutlet id menut;
    IBOutlet id menuu;
    IBOutlet NSWindow *window;
}
- (IBAction)ui_cancel:(id)sender;
- (IBAction)ui_menus:(id)sender;
- (IBAction)ui_ok:(id)sender;
@end
