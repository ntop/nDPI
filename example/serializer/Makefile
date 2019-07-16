JSON_INC = $(shell pkg-config --cflags json-c)
JSON_LIB = $(shell pkg-config --libs json-c)

NDPI_HOME = ../../
NDPI_LIB = $(NDPI_HOME)/src/lib/libndpi.a
NDPI_INC = -I$(NDPI_HOME)/src/include -I$(NDPI_HOME)/src/lib/third_party/include

FLAGS=-g

json2tlv: json2tlv.cpp
	$(CXX) -std=c++11 $(FLAGS) -o $@ json2tlv.cpp $(JSON_INC) $(NDPI_INC) -Iinclude -march=native $(JSON_LIB) $(NDPI_LIB)  -lm -Wall -Wextra

clean:
	rm -f json2tlv
