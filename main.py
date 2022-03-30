from ast import comprehension
from itertools import count
from random import randint
import time

n = 10000
startTime = time.time()
numbers = [randint(0, 10) for i in range(n)]
executionTime = time.time() - startTime


print(f"Generating {n} numers in {executionTime}s")

def makeCountDictionaryNaive(numbers: list):
    countDictionary = {}
    for number in numbers:
        if number in countDictionary:
            countDictionary[number] += 1
        else:
            countDictionary[number] = 0
    
    return countDictionary

def makeCountDictionaryLambda(numbers: list):
    occurences = map(lambda number: (number, numbers.count(number)), set(numbers))
    return list(occurences)

def makeCountDictionaryListComprehension(numbers: list):
    return [(number, numbers.count(number)) for number in numbers]

def makeCountDictionaryDictComprehension(numbers: list):
    return {number : numbers.count(number) for number in numbers}

startTime = time.time()
countDictionaryNaive = makeCountDictionaryNaive(numbers)
executionTime = time.time() - startTime
print(f"Naive solution: {executionTime}s")

startTime = time.time()
countDictionaryLambda = makeCountDictionaryLambda(numbers)
executionTime = time.time() - startTime
print(f"Lambda solution: {executionTime}s")

startTime = time.time()
countDictionaryDictComprehension = makeCountDictionaryDictComprehension(numbers)
executionTime = time.time() - startTime
print(f"Dict comprehension solution: {executionTime}s")

startTime = time.time()
countDictionaryListComprehension = makeCountDictionaryListComprehension(numbers)
executionTime = time.time() - startTime
print(f"List comprehension solution: {executionTime}s")
# print(countDictionaryNaive)
# print(countDictionarySmart)

