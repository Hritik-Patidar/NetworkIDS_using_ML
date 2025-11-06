from pandas.io.formats.format import return_docstring


def min_count_of_solution(n, shuffled, original):
    original_index = {}
    for i in range(n):
        original_index[original[i]] = i

    map_with_number = []
    for instr in shuffled:
        map_with_number.append(original_index[instr])
    # print(map_with_number)
    count = 1
    for i in range(n - 2, -1, -1):
        if map_with_number[i] < map_with_number[i + 1]:
            count += 1
        else:
            pass

    return n - count


def main():
    Num = int(input().strip())
    if Num>=11 or Num<2:
        return None
    str = input().strip()
    shuffled = []
    for i in range(Num):
        shuffled.append(input().strip())

    str = input().strip()
    original = []

    for i in range(Num):
        original.append(input().strip())

    return(min_count_of_solution(Num, shuffled, original))

if __name__ == "__main__":
    min=main()
    print(min)
