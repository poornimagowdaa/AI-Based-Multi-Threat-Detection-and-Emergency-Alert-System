ALGORITHM: AI-Based Multi-Threat Detection and Emergency Alert System

BEGIN

Step 1:
    Import all required libraries and dependencies.

Step 2:
    Establish connection with the SQLite database.

Step 3:
    Load configuration files.
        - Event information
        - Coordinate files
        - Emergency contacts
        - Database records

Step 4:
    Initialize the surveillance interface.

Step 5:
    Allow the user to select:
        - Threat Type
            • Fall
            • Fire
            • Violence
        - Surveillance Video

Step 6:
    Open the selected video.

Step 7:
    Read the video frame by frame.

Step 8:
    Preprocess every frame.
        - Resize image
        - Normalize pixel values
        - Improve image quality
        - Reduce noise

Step 9:
    Perform threat detection.

    IF selected threat is Fall THEN

        Detect human fall.
        Compute confidence score.

    ELSE IF selected threat is Fire THEN

        Detect fire region.
        Compute confidence score.

    ELSE IF selected threat is Violence THEN

        Detect violent activity.
        Compute confidence score.

    END IF

Step 10:

    IF threat detected THEN

        Determine:

            - Event Type
            - Frame Number
            - Timestamp
            - Confidence Score

Step 11:

        Classify severity level.

            IF confidence is low
                Minor

            ELSE IF confidence is medium
                Major

            ELSE
                Critical

Step 12:

        Save evidence frames.

Step 13:

        Store incident information into the SQLite database.

Step 14:

        Display detection results.

            - Threat Type
            - Confidence Score
            - Severity
            - Timestamp
            - Evidence Images

Step 15:

        Determine emergency recipients based on:

            Threat Type

            Severity Level

Step 16:

        IF alert is required THEN

            Send SMS alert.

            Send Email alert with evidence images.

            Initiate emergency voice call.

        END IF

Step 17:

        Update database status.

Step 18:

        Continue processing remaining frames.

END IF

Step 19:

    Repeat until the video ends.

Step 20:

    Release all resources.

Step 21:

    Close database connection.

END
