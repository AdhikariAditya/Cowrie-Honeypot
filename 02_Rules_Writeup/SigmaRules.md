# Sigma Rules

# Rule 1: Logging in (T1110)

title: Detection of failed login attempt  
id: 110c2c6b-a1cf-4e26-b729-2151305c6669    
description: Cowrie failed login  
author: Aditya Adhikari  
date: 2026-09-11  
logsource:  
    product: cowrie  
detection:  
    selection:  
        eventid: cowrie.login.failed  
    condition: selection  
fields:  
    - src_ip  
    - username  
    - password  
falsepositives:  
    - Legitimate password trouble  
level: low  
tags:  
    - attack.credential-access  
    - attack.t1110.001  
**---**  
title: Automatic Login Attempt by Script  
id: 921b4be2-36fc-4c77-94f8-7caf5dcb5b90  
description: Login attempt by a robot or an automated script  
author: Aditya Adhikari  
date: 2026-09-11  
logsource:  
    product: cowrie  
correlation:  
    type: event_count  
    rules:  
        - 110c2c6b-a1cf-4e26-b729-2151305c6669    
    group-by:  
        - src_ip  
    timespan: 10s  
    condition:  
        gte: 10  
fields:  
    - src_ip  
    - username  
    - password  
falsepositives:  
    - Legitimate password trouble  
level: high  
tags:  
    - attack.credential-access  
    - attack.t1110.001  
**---**  
title: Login Attempt by Human  
id: 975f5baf-ba45-4feb-818b-26e8bcffe084  
description: Login attempt by a human or human assisted machine  
author: Aditya Adhikari  
date: 2026-09-11  
logsource:  
    product: cowrie  
correlation:  
    type: event_count  
    rules:  
        - 110c2c6b-a1cf-4e26-b729-2151305c6669    
    group-by:  
        - src_ip  
    timespan: 120s  
    condition:  
        gte: 5  
fields:  
    - src_ip  
    - username  
    - password  
level: high  
falsepositives:  
    - Legitimate password trouble  
    - Bot assisted attack   
tags:  
    - attack.credential-access  
    - attack.t1110.001

# Rule 2: Executing Commands

title: Cowrie Discovery Command  
id: d6f2d051-1157-4449-b660-7aa99a62176a  
description: Cowrie possible attack  
author: Aditya Adhikari  
date: 2026-10-02  
logsource:  
    product: cowrie  
detection:  
    selection:  
        eventid: cowrie.command.input  
        input|contains:  
            - uname  
            - hostname  
            - echo  
            - export  
            - scp  
            - chmod  
    condition: selection  
fields:  
    - src_ip  
    - input  
level: informational  
tags:  
    - attack.execution  
    - attack.t1059  
**---**  
title: Automated Discovery Attack by Bot  
id: dc60da4f-4fb0-4ef9-82e7-217a3b68b389  
description: Discovery by a robot or an automated script  
author: Aditya Adhikari  
date: 2026-10-02  
correlation:  
    type: event_count  
    rules:  
        - d6f2d051-1157-4449-b660-7aa99a62176a  
    group-by:  
        - src_ip  
    timespan: 2s  
    condition:  
        gte: 3  
level: high  
tags:  
    - attack.execution  
    - attack.t1059  
**---**  
title: Discovery Attack Attempt by Human  
id: d3b20a01-140c-4ad2-ad25-e4367cd80eb4  
status: experimental  
description: Login attempt by a human or human assisted machine  
author: Aditya Adhikari  
date: 2026-10-02  
correlation:  
    type: event_count  
    rules:  
        - d6f2d051-1157-4449-b660-7aa99a62176a  
    group-by:  
        - src_ip  
    timespan: 60s  
    condition:  
        gte: 3  
level: high  
tags:  
    - attack.execution  
    - attack.t1059

# Rule 3: Ingress File Transfer

title: Cowrie File Download  
id: b00348ce-af37-4e2b-ada9-08b0ecc7a529  
status: experimental  
description: Unknown file transfer to machine.  
author: Aditya Adhikari  
date: 2026-10-02  
logsource:  
    product: cowrie  
detection:  
    selection:  
        eventid: cowrie.session.file_download  
    condition: selection  
fields:  
    - src_ip  
    - url  
    - shasum  
    - outfile  
level: medium  
tags:  
    - attack.command-and-control  
    - attack.t1105  
