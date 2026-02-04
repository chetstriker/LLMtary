import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
    
    // Set minimum and default window size for macOS
    self.setContentSize(NSSize(width: 1375, height: 700))
    self.minSize = NSSize(width: 1375, height: 700)
    self.center()
  }
}
