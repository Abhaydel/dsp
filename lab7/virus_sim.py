import random
import time
import os

FILES = [f"file_{i}.txt" for i in range(1, 21)]  # pretend we have 20 files
infected_files = set()

def spread_virus():
    target = random.choice(FILES)
    if target not in infected_files:
        infected_files.add(target)
        print(f"⚠️  {target} got infected!")

def payload():
    messages = ["System slowing down...", "Weird popup appears...", "Files encrypted? 👀"]
    print("💀 Payload running:", random.choice(messages))

def antivirus_scan():
    if infected_files:
        cleaned = random.choice(list(infected_files))
        infected_files.remove(cleaned)
        print(f"🛡️ Antivirus cleaned {cleaned}")
    else:
        print("✅ No infections found.")

def run_simulation():
    for step in range(1, 11):  # 10 rounds
        print(f"\n--- Step {step} ---")
        action = random.choice(["spread", "payload", "scan"])
        
        if action == "spread":
            spread_virus()
        elif action == "payload":
            payload()
        else:
            antivirus_scan()
        
        time.sleep(1)

    print("\nSimulation finished!")
    print("📊 Final Infected Files:", infected_files)

if __name__ == "__main__":
    run_simulation()



