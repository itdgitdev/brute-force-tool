# Khôi phục private key EVM từ phần hex còn thiếu

`brute_force_private_key.py` thử các private key 64 ký tự hex và so khớp địa chỉ EVM đích. Chương trình chạy trên máy cục bộ, hỗ trợ bốn chế độ đầu vào và tự lưu tiến độ CLI bằng SQLite.

## Cài đặt (PowerShell)

Cần Python 3.10 trở lên. Tại thư mục chứa script, tạo môi trường Python và cài hai thư viện trong `requirements.txt`:

```powershell
Set-Location D:\python\brute_force
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Checkpoint dùng module `sqlite3` có sẵn trong thư viện chuẩn Python, nên không có gói SQLite riêng trong `requirements.txt`.

Các lệnh bên dưới dùng `python` để dễ đọc. Nếu đã tạo môi trường như trên, thay `python` bằng `.\.venv\Scripts\python.exe`. Xem toàn bộ tùy chọn bằng `python .\brute_force_private_key.py --help`.

## Chạy lần đầu với `--two-blocks`

Chế độ này nhận **hai đoạn hex nguyên vẹn** A và B, chưa biết thứ tự hoặc vị trí của chúng trong khóa. Chương trình tự tính `n = 64 - len(A) - len(B)` ký tự thiếu và thử phân bổ chúng ở đầu, giữa, cuối. Khoảng giữa bằng `0` nghĩa là hai khối liền nhau.

Ví dụ chạy được ngay dùng khóa thử `000…001` và địa chỉ tương ứng:

```powershell
$blockA = '0' * 31
$blockB = ('0' * 31) + '1'
$address = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'

python .\brute_force_private_key.py --two-blocks $blockA $blockB --address $address --workers 2 --force
```

Để chạy dữ liệu của bạn, thay giá trị của ba biến rồi chạy lại dòng lệnh cuối. Mỗi block phải không rỗng và chỉ chứa ký tự hex `0–9`, `a–f`; tổng độ dài hai block không quá 64. Có thể dùng chữ hoa và tiền tố `0x`. Địa chỉ đích phải có đúng 40 ký tự hex, có hoặc không có `0x`.

Thứ tự **gửi batch** là: A–B liền nhau (`g=0`), B–A liền nhau, A–B có khoảng giữa (`g>0`), rồi B–A có khoảng giữa. Trong mỗi layout, các ký tự thiếu được thử theo giá trị hex tăng dần. Khi dùng nhiều worker, batch có thể hoàn thành lệch thứ tự gửi. Tập candidate không thay đổi theo cách ưu tiên này.

Nếu có `n` ký tự thiếu, mỗi layout có `16^n` lượt thử. Với hai block khác nhau, số layout tối đa là `(n+1)(n+2)`; nội dung block có thể khiến một số layout trùng và được loại bỏ. Ví dụ còn thiếu 6 ký tự có tối đa **56 layout × 16⁶ = 939.524.096 candidate**. Mặc định chương trình giới hạn ở 100 triệu candidate; sau khi kiểm tra phạm vi, thêm `--force` nếu muốn chạy lượt lớn hơn:

```powershell
python .\brute_force_private_key.py --two-blocks $blockA $blockB --address $address --workers 4 --force
```

## Ba chế độ còn lại

Các ví dụ sau dùng cùng địa chỉ thử ở trên. Mỗi lần chạy chỉ chọn **một** chế độ đầu vào.

### `--pattern`: biết vị trí ký tự thiếu

Chuỗi phải dài đúng 64 ký tự; mỗi `?` là một vị trí hex chưa biết. Nếu có `n` dấu `?`, chương trình thử `16^n` candidate.

```powershell
$pattern = ('0' * 63) + '?'
python .\brute_force_private_key.py --pattern $pattern --address $address --workers 2
```

### `--fragment`: có một đoạn liên tục, chưa biết vị trí

Chương trình thử đặt đoạn này ở mọi vị trí có thể. Nếu đoạn còn thiếu `n` ký tự, có `(n+1) × 16^n` lượt thử.

```powershell
$fragment = '0' * 63
python .\brute_force_private_key.py --fragment $fragment --address $address --workers 2
```

### `--sequence`: biết thứ tự các ký tự còn lại

Các ký tự đã biết phải giữ đúng thứ tự, còn vị trí ký tự thiếu chưa biết. Nếu còn thiếu `n` ký tự, có `C(64,n) × 16^n` lượt thử.

```powershell
$sequence = ('0' * 62) + '1'
python .\brute_force_private_key.py --sequence $sequence --address $address --workers 2
```

## Checkpoint: dừng và chạy tiếp

CLI tự tạo checkpoint tại `runtime\private-key-recovery\checkpoints.sqlite3`, tính từ thư mục chứa script. Trên lần chạy đầu **không cần** thêm tùy chọn checkpoint. Tiến độ được ghi khoảng mỗi 5 giây hoặc sau 100 batch hoàn thành; khi nhấn `Ctrl+C`, các batch hoàn thành được lưu trước khi thoát. Checkpoint lưu chỉ số và hash tham số, không lưu nội dung block hay private key tìm được.

Để tiếp tục, **chạy lại cùng lệnh** với cùng chế độ, block/chuỗi đầu vào, địa chỉ đích, `--batch-size` và đường dẫn checkpoint. Chương trình sẽ in dòng `Resuming:` với tiến độ đã lưu. Có thể đổi `--workers`. Checkpoint `two-blocks` tạo trước khi đổi thứ tự ưu tiên vẫn dùng được: ID batch không đổi và batch đã hoàn thành sẽ được bỏ qua. Không thêm `--restart` khi muốn tiếp tục. Nếu lượt tìm kiếm vượt giới hạn mặc định, giữ `--force` khi chạy lại:

```powershell
# Lần đầu
python .\brute_force_private_key.py --two-blocks $blockA $blockB --address $address --workers 4 --force

# Sau khi dừng: tiếp tục cùng phạm vi, có thể đổi số worker
python .\brute_force_private_key.py --two-blocks $blockA $blockB --address $address --workers 8 --force
```

Nếu đổi đầu vào, địa chỉ hoặc `--batch-size`, chương trình tạo fingerprint khác và bắt đầu một lượt tìm kiếm riêng. Lượt đã `found` trả lại khóa bằng cách dựng từ đầu vào hiện tại; lượt đã `exhausted` trả kết quả không tìm thấy ngay. Nếu muốn chạy lại từ đầu cho đúng lượt hiện tại, thêm `--restart`:

```powershell
python .\brute_force_private_key.py --two-blocks $blockA $blockB --address $address --workers 4 --force --restart
```

Tùy chọn checkpoint khác:

- `--checkpoint .\my-checkpoint.sqlite3`: dùng file SQLite khác; phải dùng lại **cùng đường dẫn** khi tiếp tục.
- `--checkpoint-interval 10`: đổi chu kỳ lưu từ 5 sang 10 giây.
- `--no-checkpoint`: chạy không lưu tiến độ; không dùng cùng `--checkpoint` hoặc `--restart`.

## Tùy chọn chung và kết quả

- `--workers N`: số worker chạy song song; nếu bỏ qua, chương trình chọn theo số CPU.
- `--batch-size N`: số candidate tối đa mỗi batch, mặc định `1000`; giữ nguyên giá trị này khi resume.
- `--max-candidates N`: giới hạn lượt thử, mặc định `100000000`. `--force` bỏ qua giới hạn, không tăng tốc độ thử.
- `--quiet`: ẩn thông tin tiến độ.

Khi tìm thấy, chương trình in `Found private key: ...` ra terminal và trả mã thoát `0`. Nếu duyệt hết mà không thấy, mã thoát là `1`; `Ctrl+C` trả `130`. Private key được in ra màn hình, vì vậy hãy lưu ý lịch sử và bản ghi terminal khi dùng dữ liệu thật.

Chạy `python -B -m unittest -v` để kiểm tra các chế độ, checkpoint và Windows `spawn`. Nếu chạy script mà không truyền tham số đầu vào, chương trình dùng fragment và địa chỉ ví dụ viết sẵn trong mã; với dữ liệu của bạn, hãy truyền tường minh chế độ và `--address`.
