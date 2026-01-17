from pyexcelerate import Workbook
from console_progressbar import ProgressBar
import threading
import time


def print_time(size):
    count = 0
    pb = ProgressBar(total=size, prefix='0%', suffix='100%', decimals=1, length=50, fill='X', zfill='-')
    expected_time = size / 9548
    tick = expected_time / 200
    rows_per_tick = tick * 9548
    while count < size:
        pb.print_progress_bar(count)
        count += rows_per_tick
        time.sleep(tick)
    pb.print_progress_bar(size)
    print('Zipping..', flush=True)


def save_to_excel(filename, rows):
    wb = Workbook()
    x = threading.Thread(target=print_time, args=(len(rows),))
    wb.new_sheet(sheet_name='Untitled', data=rows)
    x.start()
    wb.save(filename + '.xlsx')
    print('Your data is saved in ' + filename + '.xlsx')
