// RUN: %clang_cc1 %s -emit-llvm -triple x86_64-apple-darwin -o - | FileCheck %s
// rdar://11323676

@interface NSDictionary @end
@interface NSMutableDictionary : NSDictionary@end@interface CalDAVAddManagedAttachmentsTaskGroup {
    NSMutableDictionary *_filenamesToServerLocation; 
}
- (NSDictionary *)filenamesToServerLocation;
@property (readwrite, retain) NSMutableDictionary *filenamesToServerLocation;
@end 

@implementation CalDAVAddManagedAttachmentsTaskGroup
@synthesize filenamesToServerLocation=_filenamesToServerLocation;
@end

// CHECK:  [[CALL:%.*]] = call i8* @objc_getProperty
// CHECK:  [[ONE:%.*]] = bitcast i8* [[CALL:%.*]] to [[T1:%.*]]*
// CHECK:  [[TWO:%.*]] = bitcast [[T1]]* [[ONE]] to [[T2:%.*]]*
// CHECK:  ret [[T2]]* [[TWO]]

