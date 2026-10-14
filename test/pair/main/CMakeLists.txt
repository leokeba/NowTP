idf_component_register(SRCS "main.cpp")
# For a board whose supply can't sustain full power, e.g. idf.py -DNOWTP_TEST_MAX_TX_DBM=15
if(DEFINED NOWTP_TEST_MAX_TX_DBM)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE NOWTP_TEST_MAX_TX_DBM=${NOWTP_TEST_MAX_TX_DBM})
endif()
