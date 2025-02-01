---
title: "[TRAINING BCM] - Setup môi trường"
published: 2025-01-31
description: ""
image: "./logo.jpg"
tags:
  - EHC
category: "EHC TRAINING BCM"
draft: true
---

# Setup môi trường
Khi bắt đầu học về hệ điều hành Linux, việc thiết lập một môi trường thực hành là bước quan trọng đầu tiên. Sử dụng máy ảo là phương pháp phổ biến và tiện lợi, cho phép bạn dễ dàng thay đổi cấu hình mà không ảnh hưởng đến hệ thống chính. Trong bài viết này, chúng ta sẽ cùng nhau thiết lập môi trường `Linux` trên máy ảo sử dụng `VMware` và hệ điều hành `Ubuntu`.

- **VMware Pro**:

Khá là đơn giản và không còn tốn kém tiền bạc như lúc trước nữa vì giờ đây ta có thể tải VMware Pro một cách miễn phí. Ta có thể xem chi tiết hướng dẫn tải tại [đây](https://blogs.vmware.com/workstation/2024/05/vmware-workstation-pro-now-available-free-for-personal-use.html)

- **Ubuntu**:

Tiếp đến sẽ là `Ubuntu`, mình khuyến khích sử dụng `Ubuntu 22.04` hơn vì đối với mình phiên bản `Ubuntu` ấy là phiên bản hoàn hảo nhất rồi, vì lúc này các tuỳ chỉnh về cấu hình hay là phiên bản `Python` còn là `3.9` nên sẽ dễ dàng trong việc tải tài nguyên hơn. Nhưng nếu chỉ với mục đích là tìm hiểu về Linux thì ta hoàn toàn có thể tải phiên bản mới nhất luôn. Và ta có thể tải chúng tại [đây](https://ubuntu.com/download/desktop)

Sau khi tải hai thứ ở trên xong thì ta sẽ mở `VMware` ra. Ở màn hình chính ta chọn `Create a new Virtual Machine`:
![alt text](image.png)

Bấm `next` cho đến khi gặp phần như trong ảnh và chỉnh như trong ảnh:

![alt text](image-1.png)

Tiếp đến các bước sau là các bước tuỳ chỉnh cấu hình cho máy ảo nên nó sẽ phụ thuộc vào mục đích của người dùng, nên mình sẽ skip qua bước này.

Ở giao diện của máy ảo ta vừa `create` xong ta sẽ tiếp tục vào cài đặt và tuỳ chỉnh một số thứ
![alt text](image-2.png)

Ở phần `CD/DVD(Data)` ta sẽ chọn file `.iso` mà ta vừa mới tải xong
![alt text](image-3.png)

Tiếp đến là ở phần `Network` ta sẽ chọn `Bridged` hoặc ta cũng có thể để `VMnet0` (vì ở đây mình đã có config lại một số cấu hình mạng trên máy mình rồi nên mình sẽ để `VMNet0`)

![alt text](image-4.png)

Sau khi `setting` xong mọi thứ thì ta mở nó lên và bắt đầu bước `setup` hệ điều hành `Ubuntu`

- Chọn `Try or Install Ubuntu`

![alt text](image-5.png)

- Chọn `English` và `Next`

![alt text](image-6.png)

- `Next`

![alt text](image-7.png)

- Chọn `Install Buntu`

![alt text](image-8.png)

- Chọn `Interactive installation`

![alt text](image-9.png)

- `Default selection`

![alt text](image-10.png)

- Ở phần này thì ta có thể tuỳ chỉnh và không chọn cũng được

![alt text](image-11.png)

- `Earse disk`

![alt text](image-12.png)

- Tạo tài khoản và `Install`

![alt text](image-13.png)

- Sau khi đợi nó cài đặt xong hết rồi và `boot` lên rồi thì ta bấm vào phần `I Finished Installing` ở dưới

![alt text](image-14.png)

- Sau đó là mở `Terminal` và làm theo cách hành sau:

![alt text](image-15.png)

![alt text](image-16.png)

![alt text](image-17.png)

![alt text](image-18.png)

![alt text](image-19.png)

Nếu như đến đây ta sử dụng `ping 8.8.8.8` được thì tức là ta đã thành công một phần, tiếp đến là sử dụng SSH vào máy ảo của ta bằng `Terminal` của máy chính

![alt text](image-20.png)

![alt text](image-21.png)

Và như vậy là ta đã `setup` môi trường thành công

# Lời kết

Việc thiết lập môi trường Linux trên máy ảo là bước đầu tiên và vô cùng quan trọng trong hành trình học tập và làm việc với hệ điều hành mã nguồn mở này. Bằng cách sử dụng VMware và Ubuntu, bạn đã tạo ra một không gian thực hành linh hoạt, an toàn và dễ dàng tùy chỉnh. Đây là nền tảng để khám phá sâu hơn về Linux, từ những lệnh cơ bản đến các cấu hình hệ thống phức tạp.
