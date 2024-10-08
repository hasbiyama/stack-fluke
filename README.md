# stack-fluke

This project is a PoC for implementing stack fluctuation alongside PE fluctuation.

## Overview

The primary goal of this method is to bypass memory scanners. It employs the following techniques:

1. **VEH** (Vectored Exception Handler)
2. **Keyboard Hook**
3. **StackWalk64** and **STACKFRAME64**

> **Note:**
> This project does not target AV/EDR. Please ensure real-time protection is disabled during testing.

## Demo

https://github.com/user-attachments/assets/a34e453b-eb09-48bf-9def-9c7f565f5095


## How?

>> Before
>> 
![Screenshot (166)](https://github.com/user-attachments/assets/628794a5-d681-49bd-954e-de610dec4231)


>> After
>> 
![Screenshot (167)](https://github.com/user-attachments/assets/6f5818e0-90d6-44c4-b71e-6aa7b3913c55)


## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.
