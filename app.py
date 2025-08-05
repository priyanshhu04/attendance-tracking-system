import streamlit as st
import time
import boto3
import mysql.connector
from mysql.connector import Error
import pandas as pd
from datetime import datetime, date
import json
from botocore.exceptions import ClientError
import hashlib
import base64
import hmac

# Page configuration
st.set_page_config(
    page_title="Attendance Tracking System",
    page_icon="📋",
    layout="wide"
)

try:
    AWS_REGION = st.secrets["aws"]["region"]
    USER_POOL_ID = st.secrets["aws"]["user_pool_id"]
    CLIENT_ID = st.secrets["aws"]["client_id"]
    CLIENT_SECRET = st.secrets["aws"]["client_secret"]
    
    RDS_HOST = st.secrets["database"]["host"]
    RDS_USER = st.secrets["database"]["user"]
    RDS_PASSWORD = st.secrets["database"]["password"]
    RDS_DATABASE = st.secrets["database"]["database"]
except:
    st.error("Please configure your secrets.toml file")
    st.stop()

# Initialize AWS Cognito client
@st.cache_resource
def init_cognito_client():
    return boto3.client('cognito-idp', region_name=AWS_REGION)

cognito_client = init_cognito_client()

# Database connection
@st.cache_resource
def init_db_connection():
    max_attempts = 3
    delay = 2  # seconds
    for attempt in range(1, max_attempts + 1):
        try:
            connection = mysql.connector.connect(
                host=RDS_HOST,
                user=RDS_USER,
                password=RDS_PASSWORD,
                database=RDS_DATABASE,
                connect_timeout=5,  # 5 seconds timeout
                autocommit=True
            )
            return connection
        except Error as e:
            st.error(f"Database connection attempt {attempt} failed: {e}")
            if attempt < max_attempts:
                time.sleep(delay)
            else:
                st.error("Max database connection attempts exceeded. Please check your RDS settings.")
                return None

# Helper functions
def get_secret_hash(username):
    """Generate secret hash for Cognito"""
    message = username + CLIENT_ID
    key = CLIENT_SECRET.encode('utf-8')
    msg = message.encode('utf-8')
    dig = hmac.new(key, msg, hashlib.sha256).digest()
    secret_hash = base64.b64encode(dig).decode()
    return secret_hash

def sign_up_user(username, password, email):
    """Sign up a new user"""
    try:
        response = cognito_client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password,
            SecretHash=get_secret_hash(username),
            UserAttributes=[
                {'Name': 'email', 'Value': email}
            ]
        )
        return response, None
    except ClientError as e:
        return None, str(e)

def confirm_signup(username, confirmation_code):
    """Confirm user signup"""
    try:
        response = cognito_client.confirm_sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            ConfirmationCode=confirmation_code,
            SecretHash=get_secret_hash(username)
        )
        return True, None
    except ClientError as e:
        return False, str(e)

def authenticate_user(username, password):
    """Authenticate user login"""
    try:
        response = cognito_client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': get_secret_hash(username)
            }
        )
        return response['AuthenticationResult'], None
    except ClientError as e:
        return None, str(e)

def get_user_info(access_token):
    """Get user information from access token"""
    try:
        response = cognito_client.get_user(AccessToken=access_token)
        return response, None
    except ClientError as e:
        return None, str(e)

def save_user_to_db(user_id, username, email):
    """Save user to database"""
    connection = init_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            query = """
            INSERT IGNORE INTO users (user_id, username, email) 
            VALUES (%s, %s, %s)
            """
            cursor.execute(query, (user_id, username, email))
            cursor.close()
            return True
        except mysql.connector.Error as e:
            st.error(f"Database error: {e}")
            return False
    return False

def mark_attendance(user_id, username):
    """Mark attendance for user"""
    connection = init_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            today = date.today()
            
            # Check if already marked today
            check_query = """
            SELECT id FROM attendance 
            WHERE user_id = %s AND date = %s
            """
            cursor.execute(check_query, (user_id, today))
            if cursor.fetchone():
                cursor.close()
                return False, "Attendance already marked for today"
            
            # Mark attendance
            insert_query = """
            INSERT INTO attendance (user_id, username, date, check_in_time, status) 
            VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (user_id, username, today, datetime.now(), 'Present'))
            cursor.close()
            return True, "Attendance marked successfully!"
        except mysql.connector.Error as e:
            return False, f"Database error: {e}"
    return False, "Database connection failed"

def get_attendance_records():
    """Get all attendance records"""
    connection = init_db_connection()
    if connection:
        try:
            query = """
            SELECT username, date, check_in_time, status 
            FROM attendance 
            ORDER BY date DESC, check_in_time DESC
            """
            df = pd.read_sql(query, connection)
            return df
        except Exception as e:
            st.error(f"Error fetching records: {e}")
            return pd.DataFrame()
    return pd.DataFrame()

def get_user_attendance(user_id):
    """Get attendance records for specific user"""
    connection = init_db_connection()
    if connection:
        try:
            query = """
            SELECT date, check_in_time, status 
            FROM attendance 
            WHERE user_id = %s
            ORDER BY date DESC
            """
            cursor = connection.cursor()
            cursor.execute(query, (user_id,))
            records = cursor.fetchall()
            cursor.close()
            
            if records:
                df = pd.DataFrame(records, columns=['Date', 'Check-in Time', 'Status'])
                return df
            return pd.DataFrame()
        except Exception as e:
            st.error(f"Error fetching user records: {e}")
            return pd.DataFrame()
    return pd.DataFrame()

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_info' not in st.session_state:
    st.session_state.user_info = None
if 'access_token' not in st.session_state:
    st.session_state.access_token = None

# Main App
def main():
    st.title("📋 Attendance Tracking System")
    
    # Sidebar navigation
    if st.session_state.authenticated:
        st.sidebar.success(f"Welcome, {st.session_state.user_info.get('username', 'User')}!")
        
        if st.sidebar.button("Logout"):
            st.session_state.authenticated = False
            st.session_state.user_info = None
            st.session_state.access_token = None
            st.rerun()
        
        # Main navigation
        page = st.sidebar.selectbox(
            "Navigate", 
            ["Mark Attendance", "My Attendance", "Admin Dashboard"]
        )
        
        if page == "Mark Attendance":
            mark_attendance_page()
        elif page == "My Attendance":
            my_attendance_page()
        elif page == "Admin Dashboard":
            admin_dashboard_page()
            
    else:
        auth_page()

def auth_page():
    """Authentication page"""
    # Initialize session state variables if not present
    if "show_confirmation" not in st.session_state:
        st.session_state["show_confirmation"] = False
    if "pending_username" not in st.session_state:
        st.session_state["pending_username"] = ""

    st.header("🔐 Login / Sign Up")

    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        st.subheader("Login")
        with st.form("login_form"):
            username = st.text_input("Username/Email")
            password = st.text_input("Password", type="password")
            login_button = st.form_submit_button("Login")
            
            if login_button:
                if username and password:
                    with st.spinner("Authenticating..."):
                        auth_result, error = authenticate_user(username, password)
                        
                        if auth_result:
                            st.session_state.access_token = auth_result['AccessToken']
                            user_info, error = get_user_info(auth_result['AccessToken'])
                            
                            if user_info:
                                # Extract user information
                                user_attributes = {attr['Name']: attr['Value'] for attr in user_info['UserAttributes']}
                                user_data = {
                                    'user_id': user_info['Username'],
                                    'username': user_attributes.get('email', user_info['Username']),
                                    'email': user_attributes.get('email', '')
                                }
                                
                                # Save user to database
                                save_user_to_db(user_data['user_id'], user_data['username'], user_data['email'])
                                
                                st.session_state.authenticated = True
                                st.session_state.user_info = user_data
                                st.success("Login successful!")
                                st.rerun()
                            else:
                                st.error(f"Failed to get user info: {error}")
                        else:
                            st.error(f"Login failed: {error}")
                else:
                    st.error("Please enter both username and password")
    
    with tab2:
        st.subheader("Sign Up")
        with st.form("signup_form"):
            new_username = st.text_input("Username")
            new_email = st.text_input("Email")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            signup_button = st.form_submit_button("Sign Up")

            if signup_button:
                if new_username and new_email and new_password and confirm_password:
                    if new_password == confirm_password:
                        with st.spinner("Creating account..."):
                            result, error = sign_up_user(new_username, new_password, new_email)

                            if result:
                                st.success("Account created! Please check your email for verification code.")
                                st.session_state.show_confirmation = True
                                st.session_state.pending_username = new_username
                            else:
                                st.error(f"Sign up failed: {error}")
                    else:
                        st.error("Passwords do not match")
                else:
                    st.error("Please fill all fields")

        # Confirmation form shown separately (outside signup form)
        if st.session_state.show_confirmation:
            st.subheader("Confirm Account")
            with st.form("confirm_form"):
                confirmation_code = st.text_input("Verification Code")
                confirm_button = st.form_submit_button("Confirm Account")

                if confirm_button:
                    success, error = confirm_signup(st.session_state.pending_username, confirmation_code)
                    if success:
                        st.success("Account confirmed! You can now log in.")
                        st.session_state.show_confirmation = False
                    else:
                        st.error(f"Confirmation failed: {error}")

def mark_attendance_page():
    """Mark attendance page"""
    st.header("✅ Mark Attendance")
    
    user_id = st.session_state.user_info['user_id']
    username = st.session_state.user_info['username']
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.info(f"Welcome, {username}!")
        st.write(f"Current Date: {date.today().strftime('%B %d, %Y')}")
        st.write(f"Current Time: {datetime.now().strftime('%H:%M:%S')}")
    
    with col2:
        if st.button("🔄 Check In", type="primary", use_container_width=True):
            success, message = mark_attendance(user_id, username)
            if success:
                st.success(message)
                st.balloons()
            else:
                st.warning(message)

def my_attendance_page():
    """User's attendance history page"""
    st.header("📊 My Attendance History")
    
    user_id = st.session_state.user_info['user_id']
    df = get_user_attendance(user_id)
    
    if not df.empty:
        st.dataframe(df, use_container_width=True)
        
        # Statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Days", len(df))
        with col2:
            present_days = len(df[df['Status'] == 'Present'])
            st.metric("Present Days", present_days)
        with col3:
            if len(df) > 0:
                attendance_rate = (present_days / len(df)) * 100
                st.metric("Attendance Rate", f"{attendance_rate:.1f}%")
    else:
        st.info("No attendance records found.")

def admin_dashboard_page():
    """Admin dashboard page"""
    st.header("👨‍💼 Admin Dashboard")
    
    # Get all attendance records
    df = get_attendance_records()
    
    if not df.empty:
        st.subheader("All Attendance Records")
        
        # Date filter
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start Date", value=date.today().replace(day=1))
        with col2:
            end_date = st.date_input("End Date", value=date.today())
        
        # Filter data
        df['date'] = pd.to_datetime(df['date'])
        filtered_df = df[(df['date'] >= pd.Timestamp(start_date)) & (df['date'] <= pd.Timestamp(end_date))]
        
        # Display filtered data
        st.dataframe(filtered_df, use_container_width=True)
        
        # Summary statistics
        if not filtered_df.empty:
            st.subheader("📈 Summary Statistics")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Records", len(filtered_df))
            with col2:
                unique_users = filtered_df['username'].nunique()
                st.metric("Unique Users", unique_users)
            with col3:
                present_records = len(filtered_df[filtered_df['status'] == 'Present'])
                st.metric("Present Records", present_records)
            with col4:
                if len(filtered_df) > 0:
                    avg_attendance = (present_records / len(filtered_df)) * 100
                    st.metric("Overall Rate", f"{avg_attendance:.1f}%")
            
            # Download data
            csv = filtered_df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name=f"attendance_records_{start_date}_to_{end_date}.csv",
                mime="text/csv"
            )
    else:
        st.info("No attendance records found.")

if __name__ == "__main__":
    main()
