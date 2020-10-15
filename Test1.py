import time

from NetworkFlowMeter.TicToc import timing
from rich.progress import track
from rich.console import Console
from NetworkFlowMeter.Utils import addMathChar2Dict

console = Console()


class Test:
    def __init__(self):
        self.b = 20


@timing
def main():
    t = Test()
    t.a = 10
    print(t.a)
    # print(' '.join(['aaa', 1, 0, 'dd']))
    d = {
        1: 'a',
        2: 'b',
    }
    print(d.keys())

    # for step in track(range(100), console=console):
    #     time.sleep(1)

    l = [1.1]
    d = dict(test1=10)
    addMathChar2Dict(d, 'test', l)
    print(d)
    pass


if __name__ == '__main__':
    main(timerPrefix='Total Time Costs: ', timerBeep=False)
