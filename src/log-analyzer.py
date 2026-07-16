log_data = open("data/auth.log", "r")

log_content = log_data.read()

length = len(log_content)

print(length)

log_data.close()