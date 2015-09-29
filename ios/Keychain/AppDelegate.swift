//
//  AppDelegate.swift
//  Keychain
//
//  Created by Gabriel on 9/25/15.
//  Copyright © 2015 Gabriel Handford. All rights reserved.
//

import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

  var window: UIWindow?

  func application(application: UIApplication, didFinishLaunchingWithOptions launchOptions: [NSObject: AnyObject]?) -> Bool {

    var error: NSError?

    GoBindAddGenericPassword("KeybaseTest", "gabriel", "A label", "toomanysecrets", nil, &error);
    if (error != nil) {
      print("Failed: \(error)")
    } else {
      print("Add OK")
    }

    GoBindDeleteGenericPassword("KeybaseTest", "gabriel", nil, &error)
    if (error != nil) {
      print("Failed: \(error)")
    } else {
      print("Delete OK")
    }

    return true
  }


}

