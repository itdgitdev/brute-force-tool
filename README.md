# Chạy chế độ two-blocks

Hướng dẫn này dành cho PowerShell. Cần Python 3.10 trở lên. Cài các gói trong thư mục dự án:

~~~powershell
Set-Location D:\python\brute_force
python -m pip install -r requirements.txt
~~~

`requirements.txt` đã gồm `coincurve` để tăng tốc tính public key. Nếu dùng môi trường ảo, hãy dùng cùng Python của môi trường đó cho cả lệnh cài và lệnh chạy.

## Chạy lần đầu

Khai báo hai khối hex nguyên vẹn và địa chỉ EVM cần khớp. Ví dụ dưới đây dùng dữ liệu thử; thay ba giá trị trước khi tìm khóa của bạn:

~~~powershell
$blockA = '0' * 31
$blockB = ('0' * 31) + '1'
$address = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'

python .\brute_force_private_key.py --two-blocks $blockA $blockB --address $address --workers 4 --force
~~~

Mỗi block phải không rỗng, chỉ chứa ký tự hex và tổng độ dài không quá 64. Chương trình thử cả thứ tự A–B và B–A; trước hết thử hai khối liền nhau, rồi mới thử có khoảng giữa. Số ký tự thiếu là 64 trừ tổng độ dài hai block. Địa chỉ phải có đúng 40 ký tự hex, có thể thêm tiền tố 0x.

**Viết `--force` với hai dấu gạch ngang.** Tùy chọn này chỉ cho phép chạy khi vượt giới hạn mặc định 100 triệu candidate; nó không làm chương trình nhanh hơn.

## Chọn số worker

Mỗi worker là một tiến trình xử lý một batch tại một thời điểm. Bắt đầu với số **lõi vật lý** của CPU, rồi chọn theo tốc độ candidate/giây ổn định:

| CPU | Mức bắt đầu |
| --- | ---: |
| 4 lõi / 4 luồng | `--workers 4` |
| Intel i7-12700H: 14 lõi / 20 luồng | `--workers 14`; thử thêm 10 và 20 |

Với laptop, chạy từng mức 5–10 phút và giữ mức có tốc độ ổn định tốt nhất; giới hạn nhiệt và điện có thể khiến nhiều worker hơn không nhanh hơn. Nếu cần dùng máy trong lúc tìm kiếm, giảm vài worker để chừa tài nguyên.

## Dừng và chạy tiếp checkpoint

Checkpoint tự lưu tại `runtime\private-key-recovery\checkpoints.sqlite3`. Dừng bằng `Ctrl+C`, rồi chạy lại cùng lệnh để tiếp tục. Giữ nguyên hai block, địa chỉ, `--batch-size` (mặc định 1000) và đường dẫn checkpoint; có thể đổi `--workers`:

~~~powershell
python .\brute_force_private_key.py --two-blocks $blockA $blockB --address $address --workers 4 --force
~~~

Nếu trước đó đã dùng `--checkpoint PATH` riêng, hãy dùng lại đúng PATH đó. Không thêm `--restart` khi muốn tiếp tục, vì tùy chọn này bỏ tiến độ đã lưu. Checkpoint cũ vẫn dùng được sau thay đổi thứ tự ưu tiên hai khối liền nhau.

### Nếu mất điện hoặc máy tắt đột ngột

Sau khi mở máy:

1. Khai báo lại `$blockA`, `$blockB`, `$address` đúng như lần trước.
2. Chạy lại lệnh cũ:

~~~powershell
python .\brute_force_private_key.py --two-blocks $blockA $blockB --address $address --workers 4 --force
~~~

Giữ nguyên `--batch-size` và đường dẫn checkpoint nếu trước đó bạn đã đặt riêng. Có thể đổi `--workers`. **Không thêm `--restart`**; nếu báo checkpoint đang được sử dụng, đợi khoảng 30 giây rồi thử lại.
