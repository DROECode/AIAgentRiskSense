import pandas as pd
import re
# Sample dataset of deployed agents
data = {
    'Agent Name': ['Agent A', 'Agent B', 'Agent C', 'Agent D'],
    'Owner': ['Owner 1', 'Owner 2', 'Owner 3', 'Owner 4'],
    'Data Sensitivity': [5, 3, 4, 2],  # Scale 1-5
    'Autonomy Level': [4, 2, 5, 3],    # Scale 1-5
    'Decision Impact': [5, 4, 3, 2],   # Scale 1-5
    'Change Frequency': [3, 5, 2, 4]   # Scale 1-5
}
# Sample agent code for analysis
agent_code = {
    'Agent A': '''
        import os
        password = "12345"
        def process_data(data):
            print(data)
    ''',
    'Agent B': '''
        def process_data(data):
            print(data)
    ''',
    'Agent C': '''
        import pickle
        def process_data(data):
            try:
                print(data)
            except Exception as e:
                print(e)
    ''',
    'Agent D': '''
        def process_data(data):
            print(data)
    '''
}
# Convert to DataFrame
df = pd.DataFrame(data)
# Define weights for each criterion
weights = {
    'Data Sensitivity': 0.3,
    'Autonomy Level': 0.25,
    'Decision Impact': 0.25,
    'Change Frequency': 0.2
}
# Calculate metadata-based risk score
df['Risk Score'] = (
    df['Data Sensitivity'] * weights['Data Sensitivity'] +
    df['Autonomy Level'] * weights['Autonomy Level'] +
    df['Decision Impact'] * weights['Decision Impact'] +
    df['Change Frequency'] * weights['Change Frequency']
)
# Function to analyze agent code for risky patterns
def analyze_code(code):
    issues = []
    if re.search(r'password\\s*=\\s*["\'].*["\']', code):
        issues.append('Hardcoded credentials')
    if not re.search(r'try\\s*:', code):
        issues.append('Missing error handling')
    if not re.search(r'print\\s*\\(|logging\\s*\\.', code):
        issues.append('Lack of logging')
    if re.search(r'import\\s+pickle', code):
        issues.append('Insecure imports')
    if not re.search(r'if\\s+.*\\s*:', code):
        issues.append('Absence of input validation')
    return issues
# Analyze code and calculate code risk score
code_risk_scores = []
code_issues = []
for agent in df['Agent Name']:
    issues = analyze_code(agent_code[agent])
    code_issues.append(', '.join(issues))
    code_risk_scores.append(len(issues))
# Add code risk score to DataFrame
df['Code Risk Score'] = code_risk_scores
# Combine metadata and code risk into total score
df['Total Risk Score'] = df['Risk Score'] + df['Code Risk Score'] * 0.5
# Classify risk level
def classify_risk(score):
    if score >= 4:
        return 'High'
    elif score >= 2.5:
        return 'Medium'
    else:
        return 'Low'
df['Risk Level'] = df['Total Risk Score'].apply(classify_risk)
df['Code Issues'] = code_issues
# Display results
print(df[['Agent Name', 'Total Risk Score', 'Risk Level', 'Code Issues']])
