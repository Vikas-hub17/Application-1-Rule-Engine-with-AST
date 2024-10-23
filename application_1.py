import re

# Node structure for AST
class Node:
    def __init__(self, node_type, value=None, left=None, right=None):
        """
        Initialize an AST Node.
        
        Args:
        node_type (str): The type of the node, either 'operator' or 'operand'.
        value (str or dict): The condition or operator. For operands, it's a condition dict. For operators, it's 'AND' or 'OR'.
        left (Node): Left child (optional).
        right (Node): Right child (optional).
        """
        self.type = node_type
        self.value = value
        self.left = left
        self.right = right

    def __repr__(self):
        """String representation of the Node for debugging."""
        if self.type == "operator":
            return f"({self.left} {self.value} {self.right})"
        else:
            return str(self.value)

# Function to parse individual conditions (e.g., age > 30)
def parse_condition(condition_str):
    """
    Parse a condition string into a dictionary.
    
    Args:
    condition_str (str): A string like 'age > 30'.
    
    Returns:
    dict: A dictionary with 'attribute', 'operator', and 'value'.
    """
    match = re.match(r"(\w+)\s*(>|<|>=|<=|==|!=)\s*(\w+)", condition_str)
    if match:
        attribute, operator, value = match.groups()
        try:
            value = int(value)  # Try converting value to an integer
        except ValueError:
            pass  # Keep as string if it's not a number
        return {"attribute": attribute, "operator": operator, "value": value}
    else:
        raise ValueError(f"Invalid condition: {condition_str}")

# Function to create a rule (AST) from a string
def create_rule(rule_str):
    """
    Create an AST from a rule string.
    
    Args:
    rule_str (str): Rule string like 'age > 30 AND department == "Sales"'.
    
    Returns:
    Node: The root of the AST representing the rule.
    """
    rule_str = rule_str.strip()
    # Split the string into conditions and operators using regex
    tokens = re.split(r"(\sAND\s|\sOR\s)", rule_str)
    
    current_node = None
    for token in tokens:
        token = token.strip()
        if token == "AND" or token == "OR":
            # Create an operator node
            new_node = Node(node_type="operator", value=token)
            new_node.left = current_node
            current_node = new_node
        else:
            # Create an operand node (condition)
            condition = parse_condition(token)
            operand_node = Node(node_type="operand", value=condition)
            if current_node and current_node.type == "operator" and not current_node.right:
                current_node.right = operand_node
            else:
                current_node = operand_node
                
    return current_node

# Function to combine multiple rules (ASTs) into one
def combine_rules(rules, operator="AND"):
    """
    Combine multiple ASTs (rules) into one by joining them with an operator.
    
    Args:
    rules (list): A list of AST root nodes.
    operator (str): The operator to combine rules ('AND' or 'OR').
    
    Returns:
    Node: The root of the combined AST.
    """
    if not rules:
        raise ValueError("No rules to combine.")
    
    current_node = rules[0]
    
    for rule in rules[1:]:
        combined_node = Node(node_type="operator", value=operator)
        combined_node.left = current_node
        combined_node.right = rule
        current_node = combined_node
    
    return current_node

# Function to evaluate a single condition
def evaluate_condition(condition, data):
    """
    Evaluate a single condition against the data.
    
    Args:
    condition (dict): A dictionary with 'attribute', 'operator', and 'value'.
    data (dict): A dictionary of user attributes (e.g., {"age": 35, "department": "Sales"}).
    
    Returns:
    bool: True if the condition holds, False otherwise.
    """
    attribute_value = data.get(condition["attribute"])
    
    if attribute_value is None:
        return False
    
    operator = condition["operator"]
    value = condition["value"]
    
    if operator == ">":
        return attribute_value > value
    elif operator == "<":
        return attribute_value < value
    elif operator == ">=":
        return attribute_value >= value
    elif operator == "<=":
        return attribute_value <= value
    elif operator == "==":
        return attribute_value == value
    elif operator == "!=":
        return attribute_value != value
    else:
        raise ValueError(f"Unknown operator: {operator}")

# Function to evaluate the entire AST (rule) against the data
def evaluate_rule(node, data):
    """
    Evaluate the entire AST against the data.
    
    Args:
    node (Node): The root of the AST representing the rule.
    data (dict): A dictionary of user attributes.
    
    Returns:
    bool: True if the rule evaluates to True, False otherwise.
    """
    if node.type == "operand":
        return evaluate_condition(node.value, data)
    elif node.type == "operator":
        left_result = evaluate_rule(node.left, data)
        right_result = evaluate_rule(node.right, data)
        if node.value == "AND":
            return left_result and right_result
        elif node.value == "OR":
            return left_result or right_result
    return False

# Test cases
if __name__ == "__main__":
    # Create individual rules
    rule1 = create_rule("(age > 30 AND department == 'Sales') OR (age < 25 AND department == 'Marketing')")
    rule2 = create_rule("(age > 30 AND department == 'Marketing') AND (salary > 20000 OR experience > 5)")
    
    # Combine the rules with 'AND'
    combined_rule = combine_rules([rule1, rule2], operator="AND")
    
    # Test data
    data1 = {"age": 35, "department": "Sales", "salary": 60000, "experience": 3}
    data2 = {"age": 24, "department": "Marketing", "salary": 18000, "experience": 6}
    
    # Evaluate the combined rule against the test data
    print("Data 1 evaluation:", evaluate_rule(combined_rule, data1))  # Should return True
    print("Data 2 evaluation:", evaluate_rule(combined_rule, data2))  # Should return False
