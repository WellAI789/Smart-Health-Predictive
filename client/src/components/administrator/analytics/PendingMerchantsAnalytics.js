import ErrorIcon from "@mui/icons-material/Error";
import { Card, CardContent, Stack, Typography } from "@mui/material";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";

/**
 * A card that displays the amount of merchants awaiting approval from a moderator.
 *
 * @returns {@mui.material.Card}
 */
const PendingMerchantsAnalytics = () => {
  const navigate = useNavigate();
  const [data, setData] = useState({});

  useEffect(() => {
    fetch(`${API_BASE}/admin-dashboard/pending-merchants-analytics`, {
      method: "GET",
      credentials: "include",
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(response.status);
        }
        return response.json();
      })
      .then((data) => {
        setData(data);
      });
  }, []);

  return (
    <Card
      sx={{
        px: "5px",
        py: "0px",
        textAlign: "center",
        cursor: "pointer",
      }}
      onClick={() => navigate("/admin-account-approval")}
    >
      <CardContent>
        <Stack direction="row">
          <Stack direction="row" justifyContent="space-around">
            <Stack direction="row" alignItems="center" spacing={1}>
              <Typography
                variant="h4"
                sx={{
                  fontSize: {
                    xs: "1.4em",
                    sm: "1.0em",
                    md: "1.6em",
                    lg: "1.6em",
                    xl: "2.1em",
                  },
                }}
              >
                {data.amount}
              </Typography>
              <Typography
                variant="h7"
                sx={{
                  fontSize: {
                    xs: "1.0em",
                    sm: "0.9em",
                    md: "1.0em",
                    lg: "1.0em",
                    xl: "1.0em",
                  },
                }}
              >
                Partners awaiting review
              </Typography>
            </Stack>
            {data.amount > 0 && (
              <ErrorIcon sx={{ fontSize: 40, color: "red" }} />
            )}
          </Stack>
        </Stack>
      </CardContent>
    </Card>
  );
};

export default PendingMerchantsAnalytics;
