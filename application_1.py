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
    match = re.match(r"(\w+)\s*(>|<|>=|<=|==|!=)\s*(\w+|'[^']+')", condition_str)
    if match:
        attribute, operator, value = match.groups()
        value = value.strip("'")  # Remove quotes around string values
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
    # Define a regex to correctly split tokens, including parentheses
    tokens = re.findall(r'\(|\)|\sAND\s|\sOR\s|[^()ANDOR]+', rule_str)

    def get_next_token():
        """Helper to retrieve the next token from the token list."""
        return tokens.pop(0).strip() if tokens else None

    def parse_expression():
        """Parse the rule expression and build the AST."""
        stack = []
        current_node = None

        while tokens:
            token = get_next_token()

            if token == "(":
                stack.append(current_node)
                current_node = None
            elif token == ")":
                if stack:
                    previous_node = stack.pop()
                    if previous_node:
                        if previous_node.type == "operator" and not previous_node.right:
                            previous_node.right = current_node
                        current_node = previous_node
            elif token == "AND" or token == "OR":
                # Create an operator node
                new_node = Node(node_type="operator", value=token.strip())
                new_node.left = current_node
                current_node = new_node
            else:
                # It's a condition (operand)
                condition = parse_condition(token)
                operand_node = Node(node_type="operand", value=condition)
                if current_node and current_node.type == "operator" and not current_node.right:
                    current_node.right = operand_node
                else:
                    current_node = operand_node

        return current_node

    return parse_expression()

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
    
    print(f"Evaluating condition: {condition} with data: {data}")
    
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
        result = evaluate_condition(node.value, data)
        print(f"Evaluating operand: {node.value}, result: {result}")
        return result
    elif node.type == "operator":
        left_result = evaluate_rule(node.left, data)
        right_result = evaluate_rule(node.right, data)
        print(f"Evaluating operator: {node.value}, left_result: {left_result}, right_result: {right_result}")
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

def validate_rule_string(rule_str):
    """
    Validates if the rule string is well-formed. Raises an error for any invalid syntax.
    
    Args:
    rule_str (str): The rule string to validate.
    
    Raises:
    ValueError: If the rule string contains invalid syntax.
    """
    # Check for unbalanced parentheses
    if rule_str.count('(') != rule_str.count(')'):
        raise ValueError("Unbalanced parentheses in the rule string.")

    # Check for valid conditions
    condition_regex = r"(\w+)\s*(>|<|>=|<=|==|!=)\s*(\w+|'[^']+')"
    matches = re.findall(condition_regex, rule_str)
    
    # If no valid conditions found, rule is malformed
    if not matches:
        raise ValueError("No valid conditions found in rule string.")

    # Check if there are any invalid operators or if a condition lacks an operator
    if re.search(r"\bAND\b|\bOR\b", rule_str) is None:
        raise ValueError("Rule must contain at least one logical operator (AND/OR).")
    
    print("Rule validation passed.")

# Use this function in create_rule to validate the input string before creating the AST.

# Define a catalog of allowed attributes
attribute_catalog = ["age", "department", "salary", "experience"]

def validate_condition(condition):
    """
    Validates that the condition contains only allowed attributes.
    
    Args:
    condition (dict): The condition to validate.
    
    Raises:
    ValueError: If the condition contains an invalid attribute.
    """
    attribute = condition.get("attribute")
    if attribute not in attribute_catalog:
        raise ValueError(f"Invalid attribute '{attribute}' used in condition. Must be one of {attribute_catalog}.")
    
    print("Condition validation passed.")

# Modify parse_condition to include attribute validation
def parse_condition(condition_str):
    """
    Parse a condition string into a dictionary and validate it against the catalog.
    
    Args:
    condition_str (str): A string like 'age > 30'.
    
    Returns:
    dict: A dictionary with 'attribute', 'operator', and 'value'.
    """
    match = re.match(r"(\w+)\s*(>|<|>=|<=|==|!=)\s*(\w+|'[^']+')", condition_str)
    if match:
        attribute, operator, value = match.groups()
        value = value.strip("'")  # Remove quotes around string values
        try:
            value = int(value)  # Try converting value to an integer
        except ValueError:
            pass  # Keep as string if it's not a number
        condition = {"attribute": attribute, "operator": operator, "value": value}
        
        # Validate attribute against catalog
        validate_condition(condition)
        
        return condition
    else:
        raise ValueError(f"Invalid condition: {condition_str}")

def change_operator(node, new_operator):
    """
    Change the operator (AND/OR) of an existing node.
    
    Args:
    node (Node): The operator node to change.
    new_operator (str): The new operator ('AND' or 'OR').
    
    Raises:
    ValueError: If the node is not an operator node.
    """
    if node.type != "operator":
        raise ValueError("Cannot change operator of a non-operator node.")
    
    if new_operator not in ["AND", "OR"]:
        raise ValueError("Invalid operator. Use 'AND' or 'OR'.")
    
    node.value = new_operator
    print(f"Operator changed to {new_operator}.")

def change_operand_value(node, new_value):
    """
    Change the value of an operand in the AST.
    
    Args:
    node (Node): The operand node to change.
    new_value: The new value for the operand.
    
    Raises:
    ValueError: If the node is not an operand node.
    """
    if node.type != "operand":
        raise ValueError("Cannot change value of a non-operand node.")
    
    node.value["value"] = new_value
    print(f"Operand value changed to {new_value}.")

def add_subexpression(parent_node, new_node, position="right"):
    """
    Add a new sub-expression to an existing node.
    
    Args:
    parent_node (Node): The parent operator node to add the new sub-expression.
    new_node (Node): The new sub-expression to add.
    position (str): Position to add the sub-expression ('left' or 'right').
    
    Raises:
    ValueError: If the parent node is not an operator node or invalid position.
    """
    if parent_node.type != "operator":
        raise ValueError("Cannot add sub-expression to a non-operator node.")
    
    if position == "left":
        parent_node.left = new_node
    elif position == "right":
        parent_node.right = new_node
    else:
        raise ValueError("Invalid position. Use 'left' or 'right'.")
    
    print(f"Sub-expression added to {position} of {parent_node.value} node.")

# Dictionary to store user-defined functions
user_defined_functions = {}

def add_user_function(func_name, func):
    """
    Add a user-defined function to the rule engine.
    
    Args:
    func_name (str): The name of the function.
    func (callable): The function itself.
    
    Raises:
    ValueError: If the function name is invalid or already exists.
    """
    if not callable(func):
        raise ValueError(f"{func_name} is not a callable function.")
    
    if func_name in user_defined_functions:
        raise ValueError(f"Function {func_name} already exists.")
    
    user_defined_functions[func_name] = func
    print(f"User function '{func_name}' added.")

def evaluate_user_function(func_name, *args):
    """
    Evaluate a user-defined function with given arguments.
    
    Args:
    func_name (str): The name of the function.
    args: Arguments to pass to the user-defined function.
    
    Returns:
    The result of the user-defined function.
    
    Raises:
    ValueError: If the function does not exist.
    """
    if func_name not in user_defined_functions:
        raise ValueError(f"Function '{func_name}' not found.")
    
    func = user_defined_functions[func_name]
    return func(*args)

# Example user function for advanced conditions
def is_senior(age):
    return age > 60

# Adding the custom function
add_user_function("is_senior", is_senior)

# Usage: You can call evaluate_user_function("is_senior", 65) within rules or conditions.
