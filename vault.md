
 * postMessage-based vault (iPhone, laptop, etc)
       setupPurpose
       sign
       encrypt
       decrypt
       keyinfo
       
 * XMLHTTPRequest-based vault (like on device)

 * pre-seeded vault (existing device, provide auth key)
 * fresh vault (+ recovery)


device:
  - asks for if you already have another device enrolled
    - generates device local key
    - generates device auth key
    - provides device local & auth public key to other device
    other device:
    - splits mnemnonic
    - encrypts it against (this) device local key to public key
    - uploads e_{device local public_key}(m_2) w/ generated revoke key for the device (asking for a name)
      and sends e_{device local public key} to device
    - new enrolled device can now access mnemnonic

  - if not:
    - generates device local key, ideally in security chip
    - generates device auth key, ideally in security chip
    - names itself as 'initial' and generates mnemnonic + device: + 'initial'
      + m/0/0 public key, henceforth 'initial revoke key'
    - splits mnemnonic into two, m_1 and m_2
    - stores e_{device local public key}(m_1) on device
    - stores on ForgetMe e_{device local public key}(m_2), authentication: device local key, revoke key: initial revoke key
 
    - generates mnemnonic + device: recoverycard + m/0/0, henceforth: 'recoverycard revoke key'
    - generates rescue card local key, stores onto card
    - stores e_{rescue card local key}(m_1) onto card
    - stores e_{rescue card local key}(m_2) on ForgetMe, authentication: rescue card local key, revoke key: recoverycard revoke key
    

Canary service (notifies you when touched) for PINs?

