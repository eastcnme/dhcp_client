
# cp /mnt/hgfs/code/mrj/device_test/dhclient/* -af .
# make

TARGET = dhclient

#CC = arm-hisiv100nptl-linux-gcc
#CXX = arm-hisiv100nptl-linux-g++
CC = gcc

CSRCS = $(wildcard *.c)
CPPSRCS = $(wildcard *.cpp)

OBJS = $(patsubst %.c, %.o, $(wildcard *.c))
OBJS += $(patsubst %.cpp, %.o, $(wildcard *.cpp))

LIBRARY_FILE += -lrt -lm -lstdc++

FLAGS = -Wall -O2 -s -Wcast-align -Wpadded -Wpacked

$(TARGET) : $(OBJS)
	$(CC) $^ -o $@ $(FLAGS) -I$(INCLUDE_CURL_DIR) $(LIBRARY_FILE)
	
%.o: %.c 
	$(CC) $(FLAGS) -c -o $@ $< 

%.o: %.cpp
	$(CXX) $(FLAGS) -c -o $@ $<

clean:
	rm *.o $(TARGET)

.PHONY:clean

