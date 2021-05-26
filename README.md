# shadow_breaker2
Program to crack password from shadow linux file using dictionary and hash of password using message queue and multiple processes

manager is splitting dictionary into tasks and putting them on queue
worker is taking specified number of tasks from queue nad trying to crack password (you can start multiple workers at the same time)

input:
./manager -f file_with_hash.txt -s dict_file.txt -p amountOfTasks
./worker -q queue_path -p nr_of_tasks_to_take
